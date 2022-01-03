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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

const ADDRESS_ZERO = "0x0000000000000000000000000000000000000000"
const contractTiersAddress = "0x817ba0ecafD58460bC215316a7831220BFF11C80"
const contractTiersABI = `[{"inputs": [{"internalType": "address","name": "user","type": "address"}],"name": "userInfoTotal","outputs": [{"internalType": "uint256","name": "","type": "uint256"},{"internalType": "uint256","name": "","type": "uint256"}],"stateMutability": "view","type": "function"}]`

var idoCutoff = map[string]time.Time{
	"mnet":  time.Date(2021, 11, 24, 15, 0, 0, 0, time.UTC),
	"luart": time.Date(2022, 1, 3, 9, 30, 0, 0, time.UTC),
}
var idoSize = map[string]float64{
	"mnet":  150000,
	"luart": 500000,
}
var idoTiers = map[string][]float64{
	"mnet":  []float64{0, 2500, 7500, 25000, 75000, 150000},
	"luart": []float64{0, 2500, 7500, 25000, 75000, 150000},
}
var idoTiersMul = map[string][]float64{
	"mnet":  []float64{0.25, 1, 2, 4, 8, 12},
	"luart": []float64{0.25, 1, 2, 4, 8, 12},
}

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
var client *rpc.Client
var contractTiers abi.ABI

func main() {
	var err error
	db, err = sqlx.Open("postgres", Getenv("DATABASE_URL", "postgres://admin:admin@localhost/ts_tiers_api?sslmode=disable"))
	Check(err)

	client, err = rpc.DialHTTP(Getenv("ETH_RPC", "https://main-light.eth.linkpool.io/"))
	Check(err)
	contractTiers, err = abi.JSON(strings.NewReader(contractTiersABI))
	Check(err)

	mux := http.NewServeMux()
	mux.HandleFunc("/stats", handleStats)
	mux.HandleFunc("/user", handleUser)
	mux.HandleFunc("/register", handleRegister)
	mux.HandleFunc("/kyc-start", handleKycStart)
	//mux.HandleFunc("/admin/bots", handleAdminBots)
	//mux.HandleFunc("/admin/kill-bots", handleAdminKillBots)
	//mux.HandleFunc("/admin/snapshot", handleAdminSnapshot)
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
	if _, ok := idoCutoff[ido]; !ok {
		panic(fmt.Errorf("not a valid ido: " + ido))
	}
	stats := DbSelect(`select tier, sum(bonus) as bonus, count(id) as count from registrations where ido = $1 and bonus >= 0 and created_at <= $2 group by tier`, ido, idoCutoff[ido])
	RenderJson(w, J{"stats": stats})
}

func handleUser(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(r.URL.Query().Get("address"))
	account := common.HexToAddress(address)
	registrations := DbSelect(`select ido, tier, created_at from registrations where address = $1`, account.String())
	RenderJson(w, J{"registrations": registrations})
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	ido := strings.ToLower(r.URL.Query().Get("ido"))
	if time.Now().After(idoCutoff[ido]) {
		panic(fmt.Errorf("past registration deadline"))
	}
	registration := J{}
	ReqBody(r, &registration)
	account := registration["address"].(string)
	if strings.HasPrefix(account, "0x") {
		account = common.HexToAddress(account).String()
	}
	tier := MustParseInt(registration["tier"].(string))
	xrune := MustParseInt(registration["xrune"].(string))
	bonus := MustParseInt(registration["bonus"].(string))
	iphash := sha256.Sum256([]byte(ReqIP(r)))
	if tier < 0 || tier > 5 {
		RenderJson(w, J{"error": "invalid tier"})
		return
	}

	registrations := DbSelect(`select id from registrations where ido = $1 and address = $2`, ido, account)
	if len(registrations) > 0 {
		db.MustExec(`update registrations set tier = $2, xrune = $3, bonus = $4, address_terra = $5, updated_at = now() where id = $1`,
			registrations[0]["id"], tier, xrune, bonus, registration["terra"].(string))
	} else {
		db.MustExec(`insert into registrations (id, ido, address, tier, xrune, bonus, address_terra, iphash) values ($1, $2, $3, $4, $5, $6, $7, $8)`,
			SUUID(), ido, account, tier, xrune, bonus, registration["terra"].(string), fmt.Sprintf("%x", iphash[:]))
	}
	RenderJson(w, J{"message": "ok"})
}

func handleKycStart(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	kyc := DbSelect(`select * from kyc where address = $1`, address)
	if len(kyc) > 0 {
		sessionId := kyc[0]["session_id"].(string)
		resInfo, err := synapsApiCall("GET", "/v3/session/info", sessionId)
		Check(err)
		failed := false
		resStep, err := synapsApiCall("GET", "/v3/identity/details?step_id=1637911251757", sessionId)
		if err == nil {
			failed = resStep["state"].(string) == "REJECTED"
		}
		if resInfo["status"].(string) == "CANCELLED" || failed {
			sessionId = synapsGetSessionId(address)
			db.MustExec(`update kyc set session_id = $2 where id = $1`,
				kyc[0]["id"].(string), sessionId)
		}
		RenderJson(w, J{"session_id": sessionId, "verified": resInfo["status"].(string) == "VERIFIED", "failed": failed})
	} else {
		sessionId := synapsGetSessionId(address)
		db.MustExec(`insert into kyc (id, address, session_id) values ($1, $2, $3)`,
			SUUID(), address, sessionId)
		RenderJson(w, J{"session_id": sessionId, "verified": false})
	}
}

func synapsGetSessionId(address string) string {
	res, err := synapsApiCall("POST", "/v3/session/init?alias="+address, "")
	Check(err)
	return res["session_id"].(string)
}

func synapsApiCall(method string, path string, sessionId string) (map[string]interface{}, error) {
	req, err := http.NewRequest(method, "https://individual-api.synaps.io"+path, nil)
	req.Header.Set("Client-Id", Getenv("SYNAPS_CLIENT_ID", ""))
	req.Header.Set("Api-Key", Getenv("SYNAPS_API_KEY", ""))
	if sessionId != "" {
		req.Header.Set("Session-Id", sessionId)
	}
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	log.Println("synaps", method, path, string(body))
	var v map[string]interface{}
	err = json.Unmarshal(body, &v)
	return v, err
}

func fetchBots(ido string) []J {
	addresses := DbSelect(`select address, tier, xrune, iphash, created_at from registrations where ido = $1 order by xrune desc`, ido)
	iphashCount := map[string]int{}
	addressSafe := map[string]bool{}
	for _, a := range addresses {
		iphashCount[a["iphash"].(string)]++
		if iphashCount[a["iphash"].(string)] <= 3 {
			addressSafe[a["address"].(string)] = true
		}
	}
	filteredAddresses := []J{}
	for _, a := range addresses {
		if addressSafe[a["address"].(string)] {
			continue
		}
		// if iphashCount[a["iphash"].(string)] <= 3 {
		// 	continue
		// }
		// account := common.HexToAddress(a["address"].(string))
		// var resultStr string
		// Check(client.Call(&resultStr, "eth_getTransactionCount", account, "latest"))
		// nonce, ok := new(big.Int).SetString(resultStr[2:], 16)
		// if !ok {
		// 	panic("failed to parse big int: " + resultStr)
		// }
		// a["nonce"] = int(nonce.Int64())
		a["nonce"] = -1
		a["iphash_count"] = iphashCount[a["iphash"].(string)]
		filteredAddresses = append(filteredAddresses, a)
	}
	sort.Slice(filteredAddresses, func(i, j int) bool {
		if filteredAddresses[i]["iphash"].(string) == filteredAddresses[j]["iphash"].(string) {
			return filteredAddresses[i]["created_at"].(time.Time).Before(filteredAddresses[j]["created_at"].(time.Time))
		}
		return filteredAddresses[i]["iphash"].(string) < filteredAddresses[j]["iphash"].(string)
	})
	return filteredAddresses
}

func handleAdminBots(w http.ResponseWriter, r *http.Request) {
	addresses := fetchBots(strings.ToLower(r.URL.Query().Get("ido")))
	fmt.Fprintf(w, "address,iphash,created,ipcount,nonce,tier,xrune\n")
	for _, a := range addresses {
		fmt.Fprintf(w, "%v,%s,%s,%d,%d,%v,%v\n", a["address"].(string), a["iphash"].(string)[:8], a["created_at"].(time.Time).Format("2006-01-02 15:04"), a["iphash_count"].(int), a["nonce"].(int), a["tier"], a["xrune"])
	}
}

func handleAdminKillBots(w http.ResponseWriter, r *http.Request) {
	ido := strings.ToLower(r.URL.Query().Get("ido"))
	addresses := fetchBots(ido)
	for i, a := range addresses {
		db.MustExec(`update registrations set bonus = -1 where ido = $1 and address = $2`, ido, a["address"].(string))
		fmt.Fprintf(w, "killed %d\n", i+1)
	}
}

func handleAdminSnapshot(w http.ResponseWriter, r *http.Request) {
	ido := strings.ToLower(r.URL.Query().Get("ido"))
	addresses := DbSelect(`select address, address_terra, xrune, tier from registrations r where ido = $1 and xrune > 0 and bonus >= 0 and created_at <= $2 and address_terra != '' and starts_with(address_terra, 'terra') order by id`, ido, idoCutoff[ido])
	totalAllocations := float64(0)
	totalInTier := map[int]float64{}
	for i, a := range addresses {
		fmt.Println("fetching kyc", len(addresses), i+1, a)
		kycVerified := false
		sessions := DbSelect(`select id, session_id, verified from kyc where address in ($1, $2)`, a["address"].(string), a["address_terra"].(string))
		for _, s := range sessions {
			if s["verified"].(bool) {
				kycVerified = true
				continue
			}
			sessionId := s["session_id"].(string)
			resInfo, err := synapsApiCall("GET", "/v3/session/info", sessionId)
			if err == nil && resInfo["status"].(string) == "VERIFIED" {
				kycVerified = true
			}
			if kycVerified {
				db.MustExec(`update kyc set verified = true where id = $1`, s["id"].(string))
			}
		}
		a["kyc"] = kycVerified
		if !kycVerified {
			continue
		}

		// if strings.HasPrefix(a["address"].(string), "0x") {
		// 	fmt.Println("fetching tiers", len(addresses), i+1, a)
		// 	data, err := contractTiers.Pack("userInfoTotal", common.HexToAddress(a["address"].(string)))
		// 	Check(err)
		// 	var resultStr string
		// 	Check(client.Call(&resultStr, "eth_call", map[string]interface{}{
		// 		"from": ADDRESS_ZERO,
		// 		"to":   contractTiersAddress,
		// 		"data": hexutil.Bytes(data),
		// 	}, "latest"))

		// 	result, err := contractTiers.Unpack("userInfoTotal", hexutil.MustDecode(resultStr))
		// 	Check(err)
		// 	xruneb := result[1].(*big.Int)
		// 	xruneb.Div(xruneb, big.NewInt(1000000000))
		// 	xruneb.Div(xruneb, big.NewInt(1000000000))
		// 	xruneb.Div(xruneb, big.NewInt(100))
		// 	xruneb.Mul(xruneb, big.NewInt(100))
		// 	xrune := float64(xruneb.Int64())
		// 	tier := 0
		// 	for i, v := range idoTiers[ido] {
		// 		if xrune >= v {
		// 			tier = i
		// 		}
		// 	}
		// 	totalInTier[tier] += 1
		// 	totalAllocations += idoTiersMul[ido][tier]
		// 	a["xrune"] = xrune
		// 	a["tier"] = tier
		// } else {
		tier := int(a["tier"].(int64))
		totalInTier[tier] += 1
		totalAllocations += idoTiersMul[ido][tier]
		a["tier"] = tier
		a["xrune"] = float64(a["xrune"].(int64))
	}

	baseAllocation := idoSize[ido] / totalAllocations
	tierAllocations := map[int]float64{}
	fmt.Fprintf(w, "total %.2f base %.2f tiers %#v\n", totalAllocations, baseAllocation, totalInTier)
	fmt.Fprintf(w, "address,address_terra,xrune,tier,allocation\n")
	for _, a := range addresses {
		if !a["kyc"].(bool) {
			continue
		}
		tier := a["tier"].(int)
		allocation := float64(0)
		if baseAllocation*idoTiersMul[ido][tier] > 100 {
			allocation = baseAllocation * idoTiersMul[ido][tier]
		} else {
			tierAllocationCap := totalInTier[tier] * idoTiersMul[ido][tier] * baseAllocation
			if tierAllocations[tier]+100 < tierAllocationCap {
				allocation = 100
				tierAllocations[tier] += 100
			}
		}
		fmt.Fprintf(w, "%s,%s,%.2f,%d,%.2f\n", a["address"].(string), a["address_terra"].(string), a["xrune"].(float64), tier, allocation)
	}
}
