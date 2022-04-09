package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/rpc"
)

var registrationAddressType = "terra" // evm / terra
var currentIdoName = "proteus"
var currentIdoRaising = float64(300000)
var currentIdoCutoff = time.Date(2022, 4, 12, 13, 30, 0, 0, time.UTC)
var allTiers = []float64{0, 2500, 7500, 25000, 50000, 100000}
var allMultipliers = []float64{0, 1, 3, 10, 20, 40}

const allIdos = "mnet,luart,ring,remn,mint,detf,utbets,proteus"
const networks = "ethereum,terra,fantom,polygon,solana"

const ADDRESS_ZERO = "0x0000000000000000000000000000000000000000"
const contractTiersAddressEthereum = "0x817ba0ecafD58460bC215316a7831220BFF11C80"
const contractTiersAddressFantom = "0xbc373f851d1EC6aaba27a9d039948D25a6EE8036"
const contractForgeFantom = "0x2D23039c1bA153C6afcF7CaB9ad4570bCbF80F56"
const contractTiersABI = `[{"inputs": [{"internalType": "address","name": "user","type": "address"}],"name": "userInfoAmounts","outputs": [{"internalType": "uint256","name": "","type": "uint256"},{"internalType": "uint256","name": "","type": "uint256"},{ "internalType": "address[]", "name": "", "type": "address[]" }, { "internalType": "uint256[]", "name": "", "type": "uint256[]" }, { "internalType": "uint256[]", "name": "", "type": "uint256[]" }],"stateMutability": "view","type": "function"}]`
const contractTiersSimpleABI = `[{"inputs": [{"internalType": "address","name": "","type": "address"}],"name": "userInfos","outputs": [{"internalType": "uint256","name": "","type": "uint256"},{"internalType": "uint256","name": "","type": "uint256"}],"stateMutability": "view","type": "function"}]`
const contractForgeABI = `[{"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"getUserInfo","outputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]`

type J map[string]interface{}

var db *sqlx.DB
var clientEthereum *rpc.Client
var clientFantom *rpc.Client
var contractTiers abi.ABI
var contractTiersSimple abi.ABI
var contractForge abi.ABI

func main() {
	var err error
	db, err = sqlx.Open("postgres", Getenv("DATABASE_URL", "postgres://admin:admin@localhost/ts_tiers_api?sslmode=disable"))
	Check(err)

	clientEthereum, err = rpc.DialHTTP(Getenv("ETH_RPC", "https://cloudflare-eth.com"))
	Check(err)
	clientFantom, err = rpc.DialHTTP(Getenv("FANTOM_RPC", "https://rpc.fantom.network"))
	Check(err)
	contractTiers, err = abi.JSON(strings.NewReader(contractTiersABI))
	Check(err)
	contractTiersSimple, err = abi.JSON(strings.NewReader(contractTiersSimpleABI))
	Check(err)
	contractForge, err = abi.JSON(strings.NewReader(contractForgeABI))
	Check(err)

	mux := http.NewServeMux()
	mux.HandleFunc("/user-fetch", handleUserFetch)
	mux.HandleFunc("/user-register", handleUserRegister)
	mux.HandleFunc("/kyc", handleKyc)
	mux.HandleFunc("/admin/snapshot", handleAdminSnapshot)
	mux.HandleFunc("/admin/snapshot/update", handleAdminSnapshotUpdate)
	mux.HandleFunc("/", handleIndex)
	handler := middleware(mux.ServeHTTP)

	port := Getenv("PORT", "8000")
	log.Println("starting on port", port)
	log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(handler)))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	RenderJson(w, 200, J{"message": "thorstarter tiers api"})
}

// UITLS
///////////////////////////////////////////////////////////////

func (j J) Get(k string) string {
	if v, ok := j[k].(string); ok {
		return v
	}
	return ""
}

func (j J) GetInt(k string) int {
	if v, ok := j[k].(int); ok {
		return v
	}
	if v, ok := j[k].(int64); ok {
		return int(v)
	}
	if v, ok := j[k].(float64); ok {
		return int(v)
	}
	return 0
}

func (j J) GetFloat(k string) float64 {
	if v, ok := j[k].(float64); ok {
		return v
	}
	return 0
}

func (j J) GetTime(k string) time.Time {
	if v, ok := j[k].(time.Time); ok {
		return v
	}
	return time.Time{}
}

func Check(err error) {
	if err != nil {
		panic(err)
	}
}

func Getenv(key string, alt string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return alt
}

func MustParseInt(s string) int {
	i, err := strconv.Atoi(s)
	Check(err)
	return i
}

func SUUID() string {
	u := [16]byte{}
	_, err := rand.Read(u[:16])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", u)
}

func RenderJson(w http.ResponseWriter, code int, v interface{}) {
	bs, err := json.Marshal(v)
	if err != nil {
		RenderJson(w, 500, J{"error": err.Error()})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(bs)
}

func ReqBody(r *http.Request, v interface{}) {
	bs, err := io.ReadAll(r.Body)
	Check(err)
	r.Body.Close()
	Check(json.Unmarshal(bs, &v))
}

func ReqIP(r *http.Request) string {
	ip := r.Header.Get("X-REAL-IP")
	nip := net.ParseIP(ip)
	if nip != nil {
		return ip
	}

	ips := r.Header.Get("X-FORWARDED-FOR")
	sips := strings.Split(ips, ",")
	for _, ip := range sips {
		nip := net.ParseIP(ip)
		if nip != nil {
			return ip
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	Check(err)
	nip = net.ParseIP(ip)
	if nip != nil {
		return ip
	}
	return ""
}

func DbSelect(sql string, args ...interface{}) []J {
	log.Println("dbSelect:", sql)
	results := []J{}
	rows, err := db.Queryx(sql, args...)
	Check(err)
	for rows.Next() {
		result := make(map[string]interface{})
		Check(rows.MapScan(result))
		results = append(results, result)
	}
	return results
}

func middleware(handler func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("request", r.Method, r.URL.String())
		defer func() {
			if err := recover(); err != nil {
				fmt.Println("error", err)
				RenderJson(w, 500, J{"error": fmt.Sprintf("%v", err)})
			}
		}()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		handler(w, r)
	}
}

func httpGet(url string) (interface{}, error) {
	log.Println("httpGet:", url)
	res, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("httpGet: error: %d: %s", res.StatusCode, string(body))
	}
	var v interface{}
	err = json.Unmarshal(body, &v)
	return v, err
}
