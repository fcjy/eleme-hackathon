package main

import (
	"time"
	"log"
	"fmt"
	"bytes"
	"net"
	"net/http"
	"strconv"
	"os"
	"encoding/json"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/garyburd/redigo/redis"
	"github.com/julienschmidt/httprouter"
	"runtime"
	"hash/fnv"
	"math/rand"
	"syscall"
)

const localMultVmTest = true

var redisPool *redis.Pool

var foodNum int
var foodCount []int
var foodPrice []int

type userInfo struct{
	Id int
	Password string
}
var userCache map[string]userInfo
var tokenCache map[string]int
var rTokenCache []string
var foodListCache []byte


type foodItem struct{
	FoodId int `json:"food_id"`
	Count int `json:"count"`
}
type orderStruct struct{
	OrderId string `json:"id"`
	UserId int `json:"user_id"`
	Items []foodItem `json:"items"`
	Total int `json:"total"`
}

func init() {
	var rlim syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim)
	if err != nil {
	    fmt.Println("get rlimit error: " + err.Error())
	} else {
		rlim.Cur = 10000
		rlim.Max = 10000
		err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim)
		if err != nil {
		    fmt.Println("set rlimit error: " + err.Error())
		}
	}

    rdHost := os.Getenv("REDIS_HOST")
    rdPort := os.Getenv("REDIS_PORT")
    if localMultVmTest {
    	rdHost = "192.168.50.1"
    }

    redisPool = &redis.Pool{
        MaxIdle: 256,
        MaxActive: 256,
        IdleTimeout: 300 * time.Second,
        Dial: func() (redis.Conn, error) {
        	for {
		        c, err := redis.Dial("tcp", rdHost + ":" + rdPort)
		        if err != nil {
		        	time.Sleep(time.Duration(2) * time.Millisecond)
		        	continue
		        }
		        return c, err
        	}
        },
    }

    initCache()
}

func initCache() {
    dbHost := os.Getenv("DB_HOST")
    dbPort := os.Getenv("DB_PORT")	
	dbName := os.Getenv("DB_NAME")
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	if localMultVmTest {
    	dbHost = "192.168.50.1"
    }

	db, _ := sql.Open("mysql", dbUser + ":" + dbPass + "@tcp(" + dbHost + ":" + dbPort + ")/" + dbName + "?charset=utf8")
    defer db.Close();
	rows, _ := db.Query("select * from food")
	defer rows.Close()
	rc := *(getRC())
	defer rc.Close()

	foodNum = 0
	foodPrice = make([]int, 1000)
	foodCount = make([]int, 1000)
	foodListBuf := new(bytes.Buffer)
	foodListBuf.WriteString("[")
	isBeg := true
	for rows.Next() {
		var id int
		var stock int
		var price int
		rows.Scan(&id, &stock, &price)
		foodPrice[id] = price
		foodCount[id] = stock
		rc.Do("SETNX", id, stock)

		if isBeg {
			isBeg = false
		} else {
			foodListBuf.WriteString(",")
		}

		foodJson := fmt.Sprintf("{\"id\":%d,\"price\":%d,\"stock\":%d}", id, price, stock)
		foodListBuf.WriteString(foodJson)

		foodNum++
	}
	foodListBuf.WriteString("]")
	foodListCache = foodListBuf.Bytes()

	rows, _ = db.Query("select * from user")
	userCache = make(map[string]userInfo)
	for rows.Next() {
		var id int
		var name string
		var password string
		rows.Scan(&id, &name, &password)

		userCache[name] = userInfo{
			Id: id,
			Password: password,
		}
	}
	
	tokenCache = make(map[string]int)
    rTokenCache = make([]string, 0, 60000)
    rTokenCache = append(rTokenCache, "");
    for i := 1; i <= len(userCache); i++ {
		hashStr := fmt.Sprintf("token:%d", i)
		k := hash(hashStr)
		tokenCache[k] = i
        rTokenCache = append(rTokenCache, k)
	}

	println("food:", foodNum)
	println("user:", len(userCache))
}

func main() {
	defer func(){
		if err := recover(); err != nil{
			log.Println(err);
		}
	} ()

	rand.Seed(time.Now().UTC().UnixNano())
	runtime.GOMAXPROCS(runtime.NumCPU())

	go updateFoodCount();

	host := os.Getenv("APP_HOST")
	port := os.Getenv("APP_PORT")
	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "8080"
	}
	addr := fmt.Sprintf("%s:%s", host, port)

	router := httprouter.New()

	router.POST("/login", loginHandler)
	router.GET("/foods", foodsHandler)
	router.POST("/carts", postCartHandler)
	router.PATCH("/carts/:cid", patchCartHandler)
	router.POST("/orders", postOrderHandler)
	router.GET("/orders", getOrderHandler)
	router.GET("/admin/orders", adminHandler)

	http.ListenAndServe(addr, router)
}

func updateFoodCount() {
	values := make([]int, 0, foodNum)
	keys := make([]interface{}, 0, foodNum)
    for i := 1; i <= foodNum; i++ {
        keys = append(keys, i)
    }
	
	rc := *(getRC())

	responseJson := new(bytes.Buffer)
	for {
		time.Sleep(time.Duration(16) * time.Millisecond)

		res, err := redis.Values(rc.Do("MGET", keys...))
		if err != nil {
			rc.Close()
			rc = *(getRC())
			continue
		}
		redis.ScanSlice(res, &values)
		
		responseJson.Reset();
		responseJson.WriteString("[")
		for i := 0; i < foodNum; i++ {
			id, _ := keys[i].(int)
			foodCount[id] = values[i]

			//foodJson := fmt.Sprintf("{\"id\":%d,\"price\":%d,\"stock\":%d}", id, foodPrice[id], foodCount[id])
			if i != 0 {
				responseJson.WriteString(",")
			}
			//responseJson.WriteString(foodJson)
			responseJson.WriteString("{\"id\":")
			responseJson.WriteString(strconv.Itoa(id))
			responseJson.WriteString(",\"price\":")
			responseJson.WriteString(strconv.Itoa(foodPrice[id]))		
			responseJson.WriteString(",\"stock\":")
			responseJson.WriteString(strconv.Itoa(foodCount[id]))
			responseJson.WriteString("}")			
		}
		responseJson.WriteString("]")
		foodListCache = responseJson.Bytes()
	}

	rc.Close()
}

func loginHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	type inputData struct{
		Username string `json:"username"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	var input inputData
	err := decoder.Decode(&input)
	if err != nil {
		if err.Error() == "EOF" {
			responseEemptyRequest(&w)
		} else {
    		responseMalformedJson(&w)   			
		}
	} else {
		userEntity, isHave := userCache[input.Username]
		if isHave && userEntity.Password == input.Password {
			responseJson := new(bytes.Buffer)
			responseJson.WriteString("{\"user_id\":")
			responseJson.WriteString(strconv.Itoa(userEntity.Id))
			responseJson.WriteString(",\"username\":\"")
			responseJson.WriteString(input.Username)		
			responseJson.WriteString("\",\"access_token\":\"")
			responseJson.WriteString(rTokenCache[userEntity.Id])
			responseJson.WriteString("\"}")	
			response(&w, 200, responseJson.Bytes())			
			//responseJson := fmt.Sprintf("{\"user_id\":%d,\"username\":\"%s\",\"access_token\":\"%s\"}", userEntity.Id, input.Username, rTokenCache[userEntity.Id])	
			//response(&w, 200, []byte(responseJson))
		} else {
			response(&w, 403, []byte(`{"code":"USER_AUTH_FAIL","message":"用户名或密码错误"}`))
		}
	}
}

func foodsHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	uid := checkToken(r)
	if uid != -1 {
		response(&w, 200, foodListCache)
	} else {
		responseInvalidToken(&w)
	}
}

func postCartHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	type inputData struct{
		FoodId string `json:"food_id"`
		Count string `json:"count"`
	}

	uid := checkToken(r)
	if uid != -1 {
	   	responseJson := fmt.Sprintf("{\"cart_id\":\"%s%09d\"}", rTokenCache[uid], time.Now().UnixNano() % 1000000000)
		response(&w, 200, []byte(responseJson))
	} else {
		responseInvalidToken(&w)
	}
}

func patchCartHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	type inputData struct{
		FoodId int `json:"food_id"`
		Count int `json:"count"`
	}

    uid := checkToken(r)
	if uid != -1 {
		decoder := json.NewDecoder(r.Body)
		var input inputData
		err := decoder.Decode(&input)
		if err != nil {
			if err.Error() == "EOF" {
				responseEemptyRequest(&w)
			} else {
	    		responseMalformedJson(&w)   			
			}
		} else if input.FoodId <= 0 || input.FoodId > foodNum {
			response(&w, 404, []byte(`{"code":"FOOD_NOT_FOUND","message":"食物不存在"}`))
		} else {
		    cid := ps.ByName("cid")
		    if len(cid) < 9 {
		    	response(&w, 404, []byte(`{"code":"CART_NOT_FOUND","message":"篮子不存在"}`))
		    	return
		    }
		    uh := cid[0:len(cid)-9]
            cuid, isHave := tokenCache[uh]

			if isHave == false {
				response(&w, 404, []byte(`{"code":"CART_NOT_FOUND","message":"篮子不存在"}`))
			} else if uid != cuid {
				response(&w, 401, []byte(`{"code":"NOT_AUTHORIZED_TO_ACCESS_CART","message":"无权限访问指定的篮子"}`))
			} else {
				rc := *(getRC())
	    		//defer rc.Close()
				res, _ := redis.Int64Map(rc.Do("HGETALL", "cart:" + cid))

				sum := 0
                sfid := strconv.Itoa(input.FoodId)

                res[sfid] += int64(input.Count)
                if res[sfid] < 0 {
                    res[sfid] = 0
                }
				for _, value := range res {
					sum += int(value)
				}
				if sum > 3 {
					rc.Close()
					response(&w, 403, []byte(`{"code":"FOOD_OUT_OF_LIMIT","message":"篮子中食物数量超过了三个"}`))
				} else {
                    if res[sfid] > 0 {
                        rc.Do("HSET", "cart:" + cid, input.FoodId, res[sfid])
                    } else {
                        rc.Do("HDEL", "cart:" + cid, input.FoodId)
                    }
                    rc.Close()
					response(&w, 204, []byte(``))
				}
			}
		}
	} else {
		responseInvalidToken(&w)
	}
}

func postOrderHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	type inputData struct{
		CartId string `json:"cart_id"`
	}

	uid := checkToken(r)
	if uid != -1 {		
		decoder := json.NewDecoder(r.Body)
		var input inputData
		err := decoder.Decode(&input)
		if err != nil {
			if err.Error() == "EOF" {
				responseEemptyRequest(&w)
			} else {
	    		responseMalformedJson(&w)   			
			}
			return
		}

		rc := *(getRC())
		//defer rc.Close()
		rc.Send("HGET", "order", rTokenCache[uid])
		rc.Send("HGETALL", "cart:" + input.CartId)
		rc.Flush()

		//oid, _ := redis.String(rc.Do("HGET", "order", rTokenCache[uid]))
		oid, _ := redis.String(rc.Receive())
		if oid != "" {
			rc.Close()
			response(&w, 403, []byte(`{"code":"ORDER_OUT_OF_LIMIT","message":"每个用户只能下一单"}`))
		} else {
			uh := input.CartId[0:len(input.CartId)-9]
			cuid, isHave := tokenCache[uh]

			if isHave == false {
				rc.Close()
				response(&w, 404, []byte(`{"code":"CART_NOT_FOUND","message":"篮子不存在"}`))
			} else if uid != cuid {
				rc.Close()
				response(&w, 401, []byte(`{"code":"NOT_AUTHORIZED_TO_ACCESS_CART","message":"无权限访问指定的篮子"}`))
			} else {
				total := 0
				itemsBuffer := new(bytes.Buffer)
				itemsBuffer.WriteString("{\"id\":\"")
				itemsBuffer.WriteString(rTokenCache[uid])
				itemsBuffer.WriteString("\",\"user_id\":")
				itemsBuffer.WriteString(strconv.Itoa(uid))
				itemsBuffer.WriteString(",\"items\":[")

				//res, _ := redis.Int64Map(rc.Do("HGETALL", "cart:" + input.CartId))
				res, _ := redis.Int64Map(rc.Receive())

				food_id := make([]interface{}, 0, 3)
				food_count := make([]int, 0, 3)
				var food_len int

				simple := true
				for k, v := range res {
					fid, _ := strconv.Atoi(k)
					food_id = append(food_id, fid)
					value := int(v)
					food_count = append(food_count, value)

					if foodCount[fid] < value {
						rc.Close()
						response(&w, 403, []byte(`{"code":"FOOD_OUT_OF_STOCK","message":"食物库存不足"}`))
						return
					}

					// if itemsBuffer.Len() == 1 {
					// 	itemsBuffer.WriteString(fmt.Sprintf("{\"food_id\":%d,\"count\":%d}", fid, value))
					// } else {
					// 	itemsBuffer.WriteString(fmt.Sprintf(",{\"food_id\":%d,\"count\":%d}", fid, value))
					// }

					if total != 0 {
						itemsBuffer.WriteString(",")
					}
					itemsBuffer.WriteString("{\"food_id\":")
					itemsBuffer.WriteString(strconv.Itoa(fid))
					itemsBuffer.WriteString(",\"count\":")
					itemsBuffer.WriteString(strconv.Itoa(value))
					itemsBuffer.WriteString("}")	

					total += foodPrice[fid] * value

					if foodCount[fid] < 100 {
						simple = false
					}
				}

				food_len = len(food_id)

				if simple {

					for i := 0; i < food_len; i++ {
						fid := food_id[i].(int)
						rc.Send("DECRBY", fid, food_count[i])
					}

					// success
					itemsBuffer.WriteString("],\"total\":")
					itemsBuffer.WriteString(strconv.Itoa(total))
					itemsBuffer.WriteString("}")
					orderToken := rTokenCache[uid]
					rc.Send("HSET", "order",  orderToken, itemsBuffer.String())
					rc.Flush()
					rc.Close()
					response(&w, 200, []byte("{\"id\":\"" + orderToken + "\"}"))
				} else {
					for {
						rc.Do("WATCH", food_id...)

						counts := make([]int, 0, 3)
						fc, _ := redis.Values(rc.Do("MGET", food_id...))
						redis.ScanSlice(fc, &counts)
						
						toRedis := make([]interface{}, 0, 6)					

						for i := 0; i < food_len; i++ {
							counts[i] -= food_count[i]
							if counts[i] < 0 {
								rc.Do("UNWATCH", food_id...)
								rc.Close()
								response(&w, 403, []byte(`{"code":"FOOD_OUT_OF_STOCK","message":"食物库存不足"}`))
								return
							} else {
								toRedis = append(toRedis, food_id[i], counts[i])
							}
						}

						rc.Send("MULTI")
						rc.Send("MSET", toRedis...)
						queued, _ := rc.Do("EXEC")

						if queued != nil {
							break
						}
					}
					
					// success
					itemsBuffer.WriteString("],\"total\":")
					itemsBuffer.WriteString(strconv.Itoa(total))
					itemsBuffer.WriteString("}")
					orderToken := rTokenCache[uid]
					rc.Do("HSET", "order",  orderToken, itemsBuffer.String())
					rc.Close()
					response(&w, 200, []byte("{\"id\":\"" + orderToken + "\"}"))
				}
			}
		}
	} else {
		responseInvalidToken(&w)
	}
}

func getOrderHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	uid := checkToken(r)
	if uid != -1 {
		rc := *(getRC())
		defer rc.Close()

		oj, _ := redis.String(rc.Do("HGET", "order", rTokenCache[uid]))
		response(&w, 200, []byte("[" + oj + "]"))
	} else {
		responseInvalidToken(&w)
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	uid := checkToken(r)

	if userCache["root"].Id == uid {
		rc := *(getRC())
		defer rc.Close()

		res, _ := redis.Values(rc.Do("HGETALL", "order"))
		var arr []string
		redis.ScanSlice(res, &arr)

		responseJson := new(bytes.Buffer)
		responseJson.WriteString("[")
		for i := 0; i < len(arr); i += 2 {
			if i != 0 {
				responseJson.WriteString(",")
			}			
			responseJson.WriteString(arr[i + 1])
		}
		responseJson.WriteString("]")

		response(&w, 200, responseJson.Bytes())
	} else {
		responseInvalidToken(&w)
	}
}

func checkToken(r *http.Request) int {
	token := r.FormValue("access_token")
	if token == "" {
		token = r.Header.Get("Access-Token")
	}

	ret, isHave := tokenCache[token]
	if !isHave {
		return -1
	}

	return ret
}

func response(w *http.ResponseWriter, code int, json []byte) {
	(*w).WriteHeader(code)
	(*w).Write(json)
}

func responseInvalidToken(w *http.ResponseWriter) {
	response(w, 401, []byte(`{"code":"INVALID_ACCESS_TOKEN","message":"无效的令牌"}`))
}

func responseEemptyRequest(w *http.ResponseWriter) {
	response(w, 400, []byte(`{"code":"EMPTY_REQUEST","message":"请求体为空"}`))
}

func responseMalformedJson(w *http.ResponseWriter) {
	response(w, 400, []byte(`{"code":"MALFORMED_JSON","message":"格式错误"}`))
}

func checkErr(err error) {
    if err != nil {
        panic(err)
    }
}

func getIp() string {
    name, err := os.Hostname()
    if err != nil {
         fmt.Printf("Oops: %v\n", err)
         return "Error in getIp"
    }

    addrs, err := net.LookupHost(name)
    if err != nil {
        fmt.Printf("Oops: %v\n", err)
        return "Error in getIp"
    }

    return addrs[1]
}

func hash(s string) string {
    h := fnv.New32a()
    h.Write([]byte(s))
    return fmt.Sprint(h.Sum32())
}

func getRC() *redis.Conn {
	for {
		rc := redisPool.Get()
		if rc.Err() != nil {
			time.Sleep(time.Duration(3) * time.Millisecond)
			continue
		}
		return &rc
	}
}

func checkFoodId(id int) bool {
	return id > 0 && id <= foodNum
}