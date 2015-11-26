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

const localMultVmTest = false

var redisPool *redis.Pool

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
        MaxIdle: 64,
        MaxActive: 64,
        IdleTimeout: 300 * time.Second,
        Dial: func() (redis.Conn, error) {
        	for {
		        c, err := redis.Dial("tcp", rdHost + ":" + rdPort)
		        if err != nil {
		        	time.Sleep(time.Duration(16) * time.Millisecond)
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
	rTokenCache = make([]string, 11111)
	for i := 0; i < 11111; i++ {
		hashStr := fmt.Sprintf("token:%d", i)
		k := hash(hashStr)
		tokenCache[k] = i
		rTokenCache[i] = k
	}
}

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	runtime.GOMAXPROCS(runtime.NumCPU())

	defer func(){
		if err := recover(); err != nil{
			log.Println(err);
		}
	} ()

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
	router.GET("/foods", foodsHandlerFromCache)
	router.POST("/carts", postCartHandler)
	router.PATCH("/carts/:cid", patchCartHandler)
	router.POST("/orders", postOrderHandler)
	router.GET("/orders", getOrderHandler)
	router.GET("/admin/orders", adminHandler)

	http.ListenAndServe(addr, router)
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
			responseJson := fmt.Sprintf("{\"user_id\":%d,\"username\":\"%s\",\"access_token\":\"%s\"}", userEntity.Id, input.Username, rTokenCache[userEntity.Id])	
			response(&w, 200, []byte(responseJson))
		} else {
			response(&w, 403, []byte(`{"code":"USER_AUTH_FAIL","message":"用户名或密码错误"}`))
		}
	}
}

func foodsHandlerFromCache(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	uid := checkToken(r)
	if uid != -1 {
		updatefoodList()
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
		token := fmt.Sprintf("%s%09d", rTokenCache[uid], time.Now().UnixNano() % 1000000000)
	   	responseJson := fmt.Sprintf("{\"cart_id\":\"%s\"}", token)
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
	    cid := ps.ByName("cid")
	    if len(cid) < 9 {
	    	response(&w, 404, []byte(`{"code":"CART_NOT_FOUND","message":"篮子不存在"}`))
	    	return
	    }
	    cuid := cid[0:len(cid)-9]

		decoder := json.NewDecoder(r.Body)
		var input inputData
		err := decoder.Decode(&input)
		if err != nil {
			if err.Error() == "EOF" {
				responseEemptyRequest(&w)
			} else {
	    		responseMalformedJson(&w)   			
			}
		} else if !checkFoodId(input.FoodId) {
			response(&w, 404, []byte(`{"code":"FOOD_NOT_FOUND","message":"食物不存在"}`))
		} else {
			if _, isHave := tokenCache[cuid]; isHave == false {
				response(&w, 404, []byte(`{"code":"CART_NOT_FOUND","message":"篮子不存在"}`))
			} else if uid != tokenCache[cuid] {
				response(&w, 401, []byte(`{"code":"NOT_AUTHORIZED_TO_ACCESS_CART","message":"无权限访问指定的篮子"}`))
			} else {
				rc := *(getRC())
	    		defer rc.Close()
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
					response(&w, 403, []byte(`{"code":"FOOD_OUT_OF_LIMIT","message":"篮子中食物数量超过了三个"}`))
				} else {
                    if res[sfid] > 0 {
                        rc.Do("HSET", "cart:" + cid, input.FoodId, res[sfid])
                    } else {
                        rc.Do("HDEL", "cart:" + cid, input.FoodId)
                    }
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
		rc := *(getRC())
		defer rc.Close()

		oid, _ := redis.String(rc.Do("HGET", "order", rTokenCache[uid]))
		if len(oid) != 0 {
			response(&w, 403, []byte(`{"code":"ORDER_OUT_OF_LIMIT","message":"每个用户只能下一单"}`))
		} else {
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
				total := 0
				itemsBuffer := new(bytes.Buffer)
				itemsBuffer.WriteString("[")

				cuid := input.CartId[0:len(input.CartId)-9]
				if _, isHave := tokenCache[cuid]; isHave == false {
					response(&w, 404, []byte(`{"code":"CART_NOT_FOUND","message":"篮子不存在"}`))
				} else if uid != tokenCache[cuid] {
					response(&w, 401, []byte(`{"code":"NOT_AUTHORIZED_TO_ACCESS_CART","message":"无权限访问指定的篮子"}`))
				} else {
					res, _ := redis.Int64Map(rc.Do("HGETALL", "cart:" + input.CartId))
					foods := make([]interface{}, 0, 3)

					simple := true
					for key, value := range res {
						foods = append(foods, key)

						fid, _ := strconv.Atoi(key)
						total += foodPrice[fid] * int(value)
						if itemsBuffer.Len() == 1 {
							itemsBuffer.WriteString(fmt.Sprintf("{\"food_id\":%d,\"count\":%d}", fid, int(value)))
						} else {
							itemsBuffer.WriteString(fmt.Sprintf(",{\"food_id\":%d,\"count\":%d}", fid, int(value)))
						}

						if foodCount[fid] < 500 {
							simple = false
						}
					}

					if simple {
						for key, value := range res {
							rc.Do("DECRBY", key, value)

							fid, _ := strconv.Atoi(key)
							foodCount[fid] -= int(value)
						}
					} else {
						for {
							rc.Do("WATCH", foods...)

							counts := make([]int, 0, 3)
							fc, _ := redis.Values(rc.Do("MGET", foods...))
							redis.ScanSlice(fc, &counts)
							
							toRedis := make([]interface{}, 0, 6)
							for i := 0; i < len(foods); i++ {
								id, _ := foods[i].(string)

								fid, _ := strconv.Atoi(id)
								foodCount[fid] = min(foodCount[fid], int(res[id]))

								counts[i] -= int(res[id])
								if counts[i] < 0 {
									rc.Do("UNWATCH", foods...)
									response(&w, 403, []byte(`{"code":"FOOD_OUT_OF_STOCK","message":"食物库存不足"}`))
									return
								} else {
									toRedis = append(toRedis, foods[i], counts[i])
								}
							}

							rc.Send("MULTI")
							rc.Send("MSET", toRedis...)
							queued, _ := rc.Do("EXEC")

							if queued != nil {
								break
							}
						}
					}
					
					// success
					itemsBuffer.WriteString("]")
					orderToken := rTokenCache[uid]
					orderJson := fmt.Sprintf("{\"id\":\"%s\",\"user_id\":%d,\"items\":%s,\"total\":%d}", orderToken, uid, itemsBuffer.String(), total)
					rc.Do("HSET", "order",  orderToken, orderJson)
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

var foodListUpdateTimes = 0
func updatefoodList() {
	foodListUpdateTimes++

	if foodListUpdateTimes % 100 == 0 {
		values := make([]int, 0, len(foodCount))
		keys := make([]interface{}, 0, len(foodCount))
	    for i := 1; i <= 100; i++ {
	        keys = append(keys, i)
	    }
	    rc := *(getRC())
		res, _ := redis.Values(rc.Do("MGET", keys...))
		rc.Close()
		redis.ScanSlice(res, &values)

		responseJson := new(bytes.Buffer)
		responseJson.WriteString("[")
		for i := 0; i < len(keys); i++ {
			id, _ := keys[i].(int)
			foodCount[id] = values[i]

			foodJson := fmt.Sprintf("{\"id\":%d,\"price\":%d,\"stock\":%d}", id, foodPrice[id], foodCount[id])
			if i != 0 {
				responseJson.WriteString(",")
			}
			responseJson.WriteString(foodJson)
		}
		responseJson.WriteString("]")

		foodListCache = responseJson.Bytes()
	}
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

func min(x, y int) int {
	if x < y {
		return x
	} else {
		return y
	}
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
			time.Sleep(time.Duration(rand.Intn(16)) * time.Millisecond)
			continue
		}
		return &rc
	}
}

func checkFoodId(id int) bool {
	return id > 0 && id <= 100
}