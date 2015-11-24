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
)

const localMultVmTest = false

var redisPool *redis.Pool

type foodInfo struct{
	Count int
	Price int
}
var foodCache map[int]foodInfo

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
    rdHost := os.Getenv("REDIS_HOST")
    rdPort := os.Getenv("REDIS_PORT")
    if localMultVmTest {
    	rdHost = "192.168.50.1"
    }

    redisPool = &redis.Pool{
        MaxIdle: 512,
        MaxActive: 1024,
        IdleTimeout: 300 * time.Second,
        Dial: func() (redis.Conn, error) {
            c, err := redis.Dial("tcp", rdHost + ":" + rdPort)
            if err != nil {
                panic(err.Error())
            }
            return c, err
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
	rc := redisPool.Get()
	defer rc.Close()

	foodCache = make(map[int]foodInfo)
	foodListBuf := new(bytes.Buffer)
	foodListBuf.WriteString("[")
	isBeg := true
	for rows.Next() {
		var id int
		var stock int
		var price int
		rows.Scan(&id, &stock, &price)
		foodCache[id] = foodInfo{
			Count: stock,
			Price: price,
		}
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

func foodsHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	uid := checkToken(r)
	if uid != -1 {
		values := make([]int, 0, len(foodCache))
		keys := make([]interface{}, 0, len(foodCache))
	    for k, _ := range foodCache {
	        keys = append(keys, k)
	    }

	    rc := redisPool.Get()
	    defer rc.Close()

		res, _ := redis.Values(rc.Do("MGET", keys...))
		redis.ScanSlice(res, &values)

		responseJson := new(bytes.Buffer)
		responseJson.WriteString("[")
		for i := 0; i < len(keys); i++ {
			key, _ := keys[i].(string)
			id, _ := strconv.Atoi(key[11:len(key)])
			count := values[i]

			foodJson := fmt.Sprintf("{\"id\":%d,\"price\":%d,\"stock\":%d}", id, foodCache[id].Price, count)
			foodCache[id] = foodInfo{
				Price: foodCache[id].Price,
				Count: min(count, foodCache[id].Count),
			}
			if i != 0 {
				responseJson.WriteString(",")
			}
			responseJson.WriteString(foodJson)
		}
		responseJson.WriteString("]")
		response(&w, 200, responseJson.Bytes())
	} else {
		responseInvalidToken(&w)
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
		token := rTokenCache[uid]
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

    cid := ps.ByName("cid")
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
		} else if _, isHave := foodCache[input.FoodId]; !isHave {
			response(&w, 404, []byte(`{"code":"FOOD_NOT_FOUND","message":"食物不存在"}`))
		} else {
			if _, isHave := tokenCache[cid]; isHave == false {
				response(&w, 404, []byte(`{"code":"CART_NOT_FOUND","message":"篮子不存在"}`))
			} else if uid != tokenCache[cid] {
				response(&w, 401, []byte(`{"code":"NOT_AUTHORIZED_TO_ACCESS_CART","message":"无权限访问指定的篮子"}`))
			} else {
				rc := redisPool.Get()
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
		rc := redisPool.Get()
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
				if _, isHave := tokenCache[input.CartId]; isHave == false {
					response(&w, 404, []byte(`{"code":"CART_NOT_FOUND","message":"篮子不存在"}`))
				} else if uid != tokenCache[input.CartId] {
					response(&w, 401, []byte(`{"code":"NOT_AUTHORIZED_TO_ACCESS_CART","message":"无权限访问指定的篮子"}`))
				} else {
					res, _ := redis.Int64Map(rc.Do("HGETALL", "cart:" + input.CartId))
					foods := make([]interface{}, 0, 3)
					for key, _ := range res {
						foods = append(foods, key)
					}

					for {
						rc.Do("WATCH", foods...)

						counts := make([]int, 0, 3)
						fc, _ := redis.Values(rc.Do("MGET", foods...))
						redis.ScanSlice(fc, &counts)
						
						toRedis := make([]interface{}, 0, 6)
						for i := 0; i < len(foods); i++ {
							id, _ := foods[i].(string)

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

					// success
					items := make([]foodItem, 0, len(foods))
					total := 0
					for key, value := range res {
						fid, _ := strconv.Atoi(key)
						items = append(items, foodItem{
							FoodId: fid,
							Count: int(value),
						})
						total += foodCache[fid].Price * int(value)
					}
					orderToken := rTokenCache[uid]
					order := orderStruct{
						OrderId: orderToken,
						UserId: uid,
						Items: items,
						Total: total,
					}
					orderJson, _ := json.Marshal(&order)
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
		rc := redisPool.Get()
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
		rc := redisPool.Get()
		defer rc.Close()

		res, _ := redis.Values(rc.Do("HGETALL", "order"))
		var arr []string
		redis.ScanSlice(res, &arr)

		responseJson := new(bytes.Buffer)
		responseJson.WriteString("[")
		for i := 0; i < len(arr); i += 2 {
			responseJson.WriteString(arr[i + 1])
			if i != 0 {
				responseJson.WriteString(",")
			}
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

	if foodListUpdateTimes % 500 == 0 {
		rc := redisPool.Get()
		defer rc.Close()

		values := make([]int, 0, len(foodCache))
		keys := make([]interface{}, 0, len(foodCache))
	    for k, _ := range foodCache {
	        keys = append(keys, k)
	    }
		res, _ := redis.Values((rc).Do("MGET", keys...))
		redis.ScanSlice(res, &values)

		responseJson := new(bytes.Buffer)
		responseJson.WriteString("[")
		for i := 0; i < len(keys); i++ {
			id, _ := keys[i].(int)
			count := values[i]

			foodJson := fmt.Sprintf("{\"id\":%d,\"price\":%d,\"stock\":%d}", id, foodCache[id].Price, count)
			foodCache[id] = foodInfo{
				Price: foodCache[id].Price,
				Count: min(count, foodCache[id].Count),
			}
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