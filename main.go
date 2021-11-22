package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/ethereum/go-ethereum/common"
)

type J map[string]interface{}

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

func RenderJson(w http.ResponseWriter, v interface{}) {
	bs, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(500)
		RenderJson(w, J{"error": err.Error()})
	}
	w.Header().Set("Content-Type", "application/json")
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

var db *sqlx.DB

func main() {
	var err error
	db, err = sqlx.Open("postgres", Getenv("DATABASE_URL", "postgres://admin:admin@localhost/ts_tiers_api?sslmode=disable"))
	Check(err)

	mux := http.NewServeMux()
	mux.HandleFunc("/stats", handleStats)
	mux.HandleFunc("/user", handleUser)
	mux.HandleFunc("/register", handleRegister)
	mux.HandleFunc("/", handleIndex)
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("request", r.Method, r.URL.String())
		defer func() {
			if err := recover(); err != nil {
				fmt.Println("error", err)
				w.WriteHeader(500)
				RenderJson(w, J{"error": fmt.Sprintf("%v", err)})
			}
		}()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		mux.ServeHTTP(w, r)
	}

	port := Getenv("PORT", "8000")
	log.Println("starting on port", port)
	log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(handler)))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	RenderJson(w, J{"message": "thorstarter tiers api"})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	ido := strings.ToLower(r.URL.Query().Get("ido"))
	stats := DbSelect(`select tier, sum(bonus) as bonus, count(id) as count from registrations where ido = $1 group by tier`, ido)
	RenderJson(w, J{"stats": stats})
}

func handleUser(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(r.URL.Query().Get("address"))
	account := common.HexToAddress(address)
	registrations := DbSelect(`select ido, tier, bonus, created_at from registrations where address = $1`, account.String())
	RenderJson(w, J{"registrations": registrations})
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	ido := strings.ToLower(r.URL.Query().Get("ido"))
	registration := J{}
	ReqBody(r, &registration)
	account := common.HexToAddress(registration["address"].(string))
	tier := MustParseInt(registration["tier"].(string))
	xrune := MustParseInt(registration["xrune"].(string))
	bonus := MustParseInt(registration["bonus"].(string))
	iphash := sha256.Sum256([]byte(ReqIP(r)))
	if tier < 0 || tier > 5 {
		RenderJson(w, J{"error": "invalid tier"})
		return
	}

	registrations := DbSelect(`select id from registrations where ido = $1 and address = $2`, ido, account.String())
	if len(registrations) > 0 {
		RenderJson(w, J{"error": "already registered"})
		return
	}

	db.MustExec(`insert into registrations (id, ido, address, tier, xrune, bonus, iphash) values ($1, $2, $3, $4, $5, $6, $7)`,
		SUUID(), ido, account.String(), tier, xrune, bonus, fmt.Sprintf("%x", iphash[:]))
	RenderJson(w, J{"message": "ok"})
}
