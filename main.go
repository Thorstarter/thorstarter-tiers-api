package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
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
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

const allIdos = "mnet,luart,ring"
const networks = "ethereum,terra,fantom,polygon,solana"

const ADDRESS_ZERO = "0x0000000000000000000000000000000000000000"
const contractTiersAddressEthereum = "0x817ba0ecafD58460bC215316a7831220BFF11C80"
const contractTiersAddressFantom = "0xbc373f851d1EC6aaba27a9d039948D25a6EE8036"
const contractTiersABI = `[{"inputs": [{"internalType": "address","name": "user","type": "address"}],"name": "userInfoTotal","outputs": [{"internalType": "uint256","name": "","type": "uint256"},{"internalType": "uint256","name": "","type": "uint256"}],"stateMutability": "view","type": "function"}]`
const contractTiersSimpleABI = `[{"inputs": [{"internalType": "address","name": "user","type": "address"}],"name": "userInfos","outputs": [{"internalType": "uint256","name": "","type": "uint256"},{"internalType": "uint256","name": "","type": "uint256"}],"stateMutability": "view","type": "function"}]`

var allTiers = []float64{0, 2500, 7500, 25000, 75000, 150000}
var allMultipliers = []float64{0, 1, 2, 4, 8, 12}

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

var db *sqlx.DB
var clientEthereum *rpc.Client
var clientFantom *rpc.Client
var contractTiers abi.ABI
var contractTiersSimple abi.ABI

func main() {
	var err error
	db, err = sqlx.Open("postgres", Getenv("DATABASE_URL", "postgres://admin:admin@localhost/ts_tiers_api?sslmode=disable"))
	Check(err)

	clientEthereum, err = rpc.DialHTTP(Getenv("ETH_RPC", "https://cloudflare-eth.com/"))
	Check(err)
	clientFantom, err = rpc.DialHTTP(Getenv("ETH_RPC", "https://rpc.fantom.network"))
	Check(err)
	contractTiers, err = abi.JSON(strings.NewReader(contractTiersABI))
	Check(err)
	contractTiersSimple, err = abi.JSON(strings.NewReader(contractTiersSimpleABI))
	Check(err)

	mux := http.NewServeMux()
	mux.HandleFunc("/user-fetch", handleUserFetch)
	mux.HandleFunc("/user-register", handleUserRegister)

	//mux.HandleFunc("/stats", handleStats)
	//mux.HandleFunc("/user", handleUser)
	//mux.HandleFunc("/register", handleRegister)
	//mux.HandleFunc("/kyc-start", handleKycStart)
	//mux.HandleFunc("/admin/bots", handleAdminBots)
	//mux.HandleFunc("/admin/kill-bots", handleAdminKillBots)
	mux.HandleFunc("/admin/snapshot", handleAdminSnapshot)
	mux.HandleFunc("/", handleIndex)
	handler := middleware(mux.ServeHTTP)

	port := Getenv("PORT", "8000")
	log.Println("starting on port", port)
	log.Fatal(http.ListenAndServe(":"+port, http.HandlerFunc(handler)))
}

// HANDLERS
///////////////////////////////////////////////////////////////

func handleIndex(w http.ResponseWriter, r *http.Request) {
	RenderJson(w, 200, J{"message": "thorstarter tiers api"})
}

func handleUserFetch(w http.ResponseWriter, r *http.Request) {
	iphash := fmt.Sprintf("%x", sha256.Sum256([]byte(ReqIP(r))))
	user := J{"id": SUUID(), "updated_at": time.Now().Add(-1 * time.Hour)}
	refresh := r.URL.Query().Get("refresh") == "1"
	address := r.URL.Query().Get("address")
	network := r.URL.Query().Get("network")
	if !strings.Contains(networks, network) || network == "" {
		RenderJson(w, 400, J{"error": "invalid network"})
		return
	}
	if len(address) == 0 {
		RenderJson(w, 400, J{"error": "invalid address"})
		return
	}
	users := DbSelect("select * from users where address_"+network+" = $1", address)
	if len(users) > 0 {
		user = users[0]
	} else {
		user["address_"+network] = address
	}

	if iphash != user.Get("iphash") {
		db.MustExec(`insert into users_ips (id, user_id, iphash) values ($1, $2, $3)`, SUUID(), user.Get("id"), iphash)
		user["iphash"] = iphash
		refresh = true
	}

	if refresh || time.Now().Sub(user.GetTime("updated_at")) > 30*time.Minute {
		fetchUpdateUserAmounts(user)
		user["updated_at"] = time.Now()
		db.MustExec(
			`insert into users (id, address_ethereum, address_terra, address_fantom, address_polygon, amount_ethereum, amount_terra, amount_fantom, amount_polygon, amount_tclp, amount_forge, iphash, updated_at) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) on conflict (id) do update set address_ethereum = $2, address_terra = $3, address_fantom = $4, address_polygon = $5, amount_ethereum = $6, amount_terra = $7, amount_fantom = $8, amount_polygon = $9, amount_tclp = $10, amount_forge = $11, iphash = $12, updated_at = $13`,
			user.Get("id"),
			user.Get("address_ethereum"),
			user.Get("address_terra"),
			user.Get("address_fantom"),
			user.Get("address_polygon"),
			user.GetInt("amount_ethereum"),
			user.GetInt("amount_terra"),
			user.GetInt("amount_fantom"),
			user.GetInt("amount_polygon"),
			user.GetInt("amount_tclp"),
			user.GetInt("amount_forge"),
			user.Get("iphash"),
			user.GetTime("updated_at"),
		)
	}

	delete(user, "iphash")
	registrations := DbSelect("select * from users_registrations where user_id = $1", user.Get("id"))
	baseAllocation, snapshotUsers := snapshot("ring", 400000)
	userInSnapshot := false
	userAllocation := float64(0)
	for _, user := range snapshotUsers {
		if user.Get("user_id") == user.Get("id") {
			userInSnapshot = true
			userAllocation = user["allocation"].(float64)
			break
		}
	}
	RenderJson(w, 200, J{
		"user":           user,
		"registrations":  registrations,
		"luart2x":        strings.Contains(luart2x, address),
		"baseAllocation": baseAllocation,
		"userInSnapshot": userInSnapshot,
		"userAllocation": userAllocation,
	})
}

func fetchUpdateUserAmounts(user J) {
	// Ethereum
	if address := user.Get("address_ethereum"); address != "" {
		data, err := contractTiers.Pack("userInfoTotal", common.HexToAddress(address))
		Check(err)
		var resultStr string
		err = clientEthereum.Call(&resultStr, "eth_call", map[string]interface{}{
			"from": ADDRESS_ZERO,
			"to":   contractTiersAddressEthereum,
			"data": hexutil.Bytes(data),
		}, "latest")
		if err == nil {
			result, err := contractTiers.Unpack("userInfoTotal", hexutil.MustDecode(resultStr))
			Check(err)
			amountb := result[1].(*big.Int)
			amountb.Div(amountb, big.NewInt(1000000000))
			amountb.Div(amountb, big.NewInt(1000000000))
			user["amount_ethereum"] = int(amountb.Int64())
		} else {
			log.Println("fetchUpdateUserAmounts: ethereum:", address, err)
		}
	}

	// Terra
	if address := user.Get("address_terra"); address != "" {
		b64query := base64.URLEncoding.EncodeToString([]byte(`{"user_state":{"user":"` + address + `"}}`))
		result, err := httpGet(`https://fcd.terra.dev/terra/wasm/v1beta1/contracts/terra18s7n93ja9nh37mttu66rhtsw05dxrcpsmw0c45/store?query_msg=` + b64query)
		if err == nil {
			state := result.(map[string]interface{})["query_result"].(map[string]interface{})
			balance := big.NewInt(int64(MustParseInt(state["balance"].(string))))
			balance.Div(balance, big.NewInt(1000000))
			user["amount_terra"] = int(balance.Int64())
		} else {
			log.Println("fetchUpdateUserAmounts: terra:", address, err)
		}
	}

	// Fantom
	if address := user.Get("address_fantom"); address != "" {
		data, err := contractTiersSimple.Pack("userInfos", common.HexToAddress(address))
		Check(err)
		var resultStr string
		err = clientFantom.Call(&resultStr, "eth_call", map[string]interface{}{
			"from": ADDRESS_ZERO,
			"to":   contractTiersAddressFantom,
			"data": hexutil.Bytes(data),
		}, "latest")
		if err == nil {
			result, err := contractTiers.Unpack("userInfos", hexutil.MustDecode(resultStr))
			Check(err)
			amountb := result[1].(*big.Int)
			amountb.Div(amountb, big.NewInt(1000000000))
			amountb.Div(amountb, big.NewInt(1000000000))
			user["amount_fantom"] = int(amountb.Int64())
		} else {
			log.Println("fetchUpdateUserAmounts: fantom:", address, err)
		}
	}

	// TC LP
	if address := user.Get("address_ethereum"); address != "" {
		unitsStr := ""
		poolName := "ETH.XRUNE-0X69FA0FEE221AD11012BAB0FDB45D444D3D2CE71C"
		res, err := httpGet("https://midgard.thorchain.info/v2/member/" + address)
		if err == nil {
			for _, i := range res.(map[string]interface{})["pools"].([]interface{}) {
				pool := i.(map[string]interface{})
				if pool["pool"].(string) == poolName {
					unitsStr = pool["liquidityUnits"].(string)
				}
			}
		} else {
			res, err = httpGet("https://multichain-asgard-consumer-api.vercel.app/api/v3/member/poollist?address=" + address)
			if err == nil {
				for _, i := range res.([]interface{}) {
					pool := i.(map[string]interface{})
					if pool["pool"].(string) == poolName {
						unitsStr = pool["poolunits"].(string)
					}
				}
			} else {
				log.Println("fetchUpdateUserAmounts: tclp:", address, err)
			}
		}

		if unitsStr != "" {
			poolI, err := httpGet("https://midgard.thorchain.info/v2/pool/" + poolName)
			if err == nil {
				pool := J(poolI.(map[string]interface{}))
				units := big.NewInt(int64(MustParseInt(unitsStr)))
				unitsTotal := big.NewInt(int64(MustParseInt(pool.Get("liquidityUnits"))))
				depth := big.NewInt(int64(MustParseInt(pool.Get("assetDepth"))))
				units.Mul(units, depth)
				units.Div(units, unitsTotal)
				units.Div(units, big.NewInt(100000000))
				user["amount_tclp"] = int(units.Int64())
			} else {
				log.Println("fetchUpdateUserAmounts: tclp:", err)
			}
		}
	}
}

func snapshot(ido string, size float64) (float64, []J) {
	users := DbSelect(`select r.id, r.user_id, r.address, u.iphash, (u.amount_ethereum + u.amount_terra + u.amount_fantom + u.amount_polygon + u.amount_tclp + u.amount_forge) as total from users_registrations r inner join users u on u.id = r.user_id where r.ido = $1 order by r.created_at`, ido)

	totalAllocations := float64(0)
	totalInTier := map[int]float64{}
	tierAllocations := map[int]float64{}
	iphashes := map[string]int{}

	for i, user := range users {
		if iphashes[user.Get("iphash")] >= 3 {
			continue
		}
		iphashes[user.Get("iphash")]++

		total := float64(user.GetInt("total"))
		tier := int(0)
		for i = len(allTiers) - 1; i > 0; i-- {
			if total >= allTiers[i] {
				tier = i
				break
			}
		}
		totalInTier[tier] += 1
		totalAllocations += allMultipliers[tier]
		if strings.Contains(luart2x, user.Get("address")) {
			totalAllocations += allMultipliers[tier]
		}
		user["tier"] = tier
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Get("id") > users[j].Get("id")
	})

	baseAllocation := size / totalAllocations
	for _, user := range users {
		tier := user.GetInt("tier")
		allocation := float64(0)
		if baseAllocation*allMultipliers[tier] > 100 {
			allocation = baseAllocation * allMultipliers[tier]
		} else {
			tierAllocationCap := totalInTier[tier] * allMultipliers[tier] * baseAllocation
			if tierAllocations[tier]+100 < tierAllocationCap {
				allocation = 100
				tierAllocations[tier] += 100
			}
		}
		if strings.Contains(luart2x, user.Get("address")) {
			allocation = allocation * 2
		}
		user["allocation"] = allocation
	}

	return baseAllocation, users
}

func handleUserRegister(w http.ResponseWriter, r *http.Request) {
	ido := r.URL.Query().Get("ido")
	userId := r.URL.Query().Get("user_id")
	address := r.URL.Query().Get("address")
	if !strings.Contains(allIdos, ido) {
		RenderJson(w, 400, J{"error": "invalid ido"})
		return
	}
	if len(userId) == 0 {
		RenderJson(w, 400, J{"error": "invalid user_id"})
		return
	}
	if len(address) == 0 {
		RenderJson(w, 400, J{"error": "invalid address"})
		return
	}
	registrations := DbSelect("select * from users_registrations where user_id = $1 and ido = $2", userId, ido)
	if len(registrations) == 0 {
		db.MustExec("insert into users_registrations (id, ido, user_id, address) values ($1, $2, $3, $4)", SUUID(), ido, userId, address)
	} else {
		db.MustExec("update users_registrations set address = $2 where id = $1", registrations[0].Get("id"), address)
	}
	RenderJson(w, 200, J{})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	ido := strings.ToLower(r.URL.Query().Get("ido"))
	if _, ok := idoCutoff[ido]; !ok {
		panic(fmt.Errorf("not a valid ido: " + ido))
	}
	stats := DbSelect(`select tier, sum(bonus) as bonus, count(id) as count from registrations where ido = $1 and bonus >= 0 and created_at <= $2 group by tier`, ido, idoCutoff[ido])
	RenderJson(w, 200, J{"stats": stats})
}

func handleUser(w http.ResponseWriter, r *http.Request) {
	address := strings.ToLower(r.URL.Query().Get("address"))
	if strings.HasPrefix(address, "0x") {
		address = common.HexToAddress(address).String()
	}
	registrations := DbSelect(`select ido, tier, created_at from registrations where address = $1`, address)
	RenderJson(w, 200, J{"registrations": registrations})
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
		RenderJson(w, 400, J{"error": "invalid tier"})
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
	RenderJson(w, 200, J{"message": "ok"})
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
		RenderJson(w, 200, J{"session_id": sessionId, "verified": resInfo["status"].(string) == "VERIFIED", "failed": failed})
	} else {
		sessionId := synapsGetSessionId(address)
		db.MustExec(`insert into kyc (id, address, session_id) values ($1, $2, $3)`,
			SUUID(), address, sessionId)
		RenderJson(w, 200, J{"session_id": sessionId, "verified": false})
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
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("synapsApiCall: error: %d: %s", res.StatusCode, string(body))
	}
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
		// Check(clientEthereum.Call(&resultStr, "eth_getTransactionCount", account, "latest"))
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
	/*
		  CHECK KYC
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
	*/
	baseAllocation, users := snapshot("ring", 400000)
	fmt.Fprintf(w, "base %.2f\n", baseAllocation)
	fmt.Fprintf(w, "address,total,tier,allocation\n")
	for _, user := range users {
		fmt.Fprintf(
			w, "%s,%d,%d,%.2f\n",
			user.Get("address"), user.GetInt("total"),
			user.GetInt("tier"), user["allocation"].(float64),
		)
	}
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

const luart2x = `0x41B720be5796ECb7BEB5f712e1cC57dE631240c0,
0x6fa398877821C285B961a48A2d315B54c129BCA5,
0x2b0A6d28CE1d149201323971a8BDC544795cf7eB,terra16zrhr55k9syrlmeqtae9ahccpgld843gu04qp6
0x46adF4507A9eE9333418774628fc70347a6d119E,terra18w5x4jw2kn73tlcu43urnh5y6wt0ddw3vsk9sq
0x586724B895eA7e866fB743A887a564BF61490f38,terra1hmeaq2xezhvgchgx7yaq0tmmvdjch68v2przn0
0x53774c6954f322226ce92396A95A21Bd30225C5b,terra1d2munkhm7875az4ckaaych8tw9agxp749tnag8
0x855Fa5B6194358142ffb487d5070176eA0D5F80a,terra1nelmz2ehlgl8lnd0q4rckshm9lcyxnxnc9d499
0x914F7592F9c7969ff0A098C2C1d64F10c3407255,terra1uzhmpw69zl3hvepal2rz58rwpef0gzz7suh83c
0x346053f3a5D5352F3c109f71129009596C7e601A,terra1e33u6l63j95xra55rvmsdse53ewcg36vs7k6nl
0xF2b24065c62a606241D6D3615f171BDb889916F7,terra15ty3pwlk20zc93c3s20acvhw2gamdzd4nglxre
0x07dEf5481cfbcDaCAC9618725dd209686cd9A0a8,terra13s7qnmxn2rvlrtn2jzjjktnya86zflk4trxwq7
0x672e09EA456141A77fdeeC813222b4Ad7c22f8EC,terra1jd8r99rrnnhyahfvck8glda5nv8s2fyehag0rr
0x0CeB9dDC3aab8abFBEfc828AF9E219703362F3F0,terra1pa79w0a5smfdredv736v3nfmqnat706k2g5h4v
0xaa0CBD2396f13b2967347fDcc13a183CA715e3B8,terra1cha7drule93c0uh0g8jvkpd9e7gfycswv04phy
0xA4E3E6917DA1067f917Ac976b26bc1202e9DfEBd,terra1g03ddpa6hwknzn0gymtjdp6ctpjqe7xerw7fmp
0x581b2364eD7178B66c1DBD61ADe7688cC49F547b,terra1cq9zcrlzl2ufg5c4wr7689p7tak483p38rs4e2
0xA168baA7010E3C68230567379bE40bd3fb88D25E,terra1hnkl869aj8fh8u8qcyarqal7apyravsqat7r2e
0x3344e8AecB3fCDdc4dfcd13A5F431Af6495848A0,terra14ma07rueznyffrza4684nl7fhtwpgupvls2pvr
0x941c43b1f3E35FC934e427d5898f3b5C42b1eC70,terra1yfdt9jv3jn823d0wcsvkn5q2qyv29x3xw638k0
0x9331754076270AF7cBf803D02f5d57c5343f34BB,terra1j74x8ny08c54ycuqvuy6u6cz2yf0efh6cgrsc8
0x285c49Da74886682ab72F8212D2905c5C2a52F14,terra1wxgvzhlmeyvueqfuy9ynzj4skg7dxsvrp9ftuq
0x5CFbA7573E21074F62Ed5891698f5D69dd0bAA51,terra16e4de7dmr0erzjt39ffwty4mlaevrvwrrkzxym
0x7D4FBecC8c50D059AFD1959fcF97c642Ac84e610,terra1jusyeqt7rglplxyhe2n60sldu62d8789fhyc87
0xaa16D68C56450bBf86b9e9b2eafdd6Ebce72fEA6,terra1zz3rxn5hn5fvsm0nhya0lz3kju85rj2l2h0nak
0x2417ea5164FAf4664E7B6903DC275B1B9a258b56,terra1ggadup0w2k0ls336z3kq9m2sw6tnplex8q436t
0x54e8d599f9d381C58F775d99000f09B283e96E44,terra1effqqmfny9p6zsx53u7r9xywx7mma6f5stda0u
0x02a89E6457AB9875C4958C5f784816FAacFCFaC3,terra1try592gptkmx42e00qhs6dpvhlwn2xygy8ru0e
0xE7026eaD5Ce701558Bdd20B85aD0F4A8C47F09e2,terra1l8l6qsw53e87vr8t3s68dw36yj3hfe7f576xju
0xD6DeFcD4541fB0B63bcB27216425a280B1aB29eD,terra1m936h80ks626lcfadg05l803gj89u7kv6sw6ys
0xdE32C7ABA0169F81f74A6728A061ec1Ec153A894,terra1glqz30ptnk8ngl3ts4xxxyg3ngkg3pefrxep23
0xDAb0c0654d65C48b7af1672d9375831EA4AdC9dB,terra1l5jx4zg90made0dvfh358r8rvzfm8ndfvm6lgd
0xB9764b82ef6AE4402F53E2Dc7B688ded8fAd1A3b,terra13ykcahp06t0n8ulgggfnhktfmtzw0lle0fn0y0
0xA7C3d857803216257037Bd998c9587EB3CD50d46,terra1htrgfmjjmvsxl5eytqslt26v3fccqc5gcmyad4
0xb0bE8e4351ebd9Fa96D5D30541DD6f23d7931174,terra1l96as46ytfsrs0z2kx5fj5fsqkd6u0qdrzet9t
0xc2338d5CC0827C9A5Bef001Cbed39711E8EFa97d,terra19vxppgejra6z3q4zx5kn7cu7k0hsj8xa9mtwye
0x1b0C46314Ea572eb47eed73bB2BA72323cBfBbe0,terra19lypdvmgqhttekwgsruj7tc72tesmj59r4wky3
0x5570b3EdfC9ce9DbbfbF8E22f24011d64Fc88F25,terra1sfm5wwsa3nn28c535rruke32j8unff2lvqre3x
0x4A2A7f194b2714e0c936f5859d0B196C84aaE629,terra1t2fcyxl952xj5rz0wxww9y6azex5naffsmvh8l
0x2Be841f84D08De41daD098E7B2C03C4507eB4789,terra1yaj5yspvaemtf5nurtfsf59mxedl503zjv35yy
0x406e1f40ED26d799412e9aC1E7E965800B53F8B5,terra1l6kz96ju3cg8ppkx8hax5qw6nzt7esanmyurvd
0xE2e18e5810b72B3691D1a72941Da39c423882dd0,terra1n5xf6tdj4ladqwl9cqlu9yd5k8t3kexc3avwkm
0xABfeAaeB635a4eE3Feca6BE5748A52854CA0aeaF,terra1r73rqn0fsga4dvm785z8pewgmj68jqemwhqyug
0xf7c6382Da0A3ee08aD4c201b01E33e122600Ab6f,terra1qutp9fzjtgw2wys9jdw5ltz87pkzh9cp0uk8uf
0x6110bFBEDa30680b41F29294160E33E7608beF11,terra1rfuryj2yfklafswyz7al50mgssswwpyeztx2n0
0x4Ac0594f7cc48A1c3F93ED77C8bb3E09a6Fc7F87,terra18pfrq33fjxajdv4c4dj7vdrpmsg4sdnap5y4zt
0x4f7F9AF12a05F3EC4088735534aE849e2850030C,terra1a96fhrvajfcs05fj66d8z9qg3zd8zttmyex70l
0x80d221b17BDc13c910d54EA85909269BAe2Ae08f,terra1vae9ur3r8yvlautw4mrs3gw5da62y7kgm0muvh
0x72bb7a460Cc05e3B795636609b2d42903642EC32,terra1jewn56kl9ykhgyd098ptqx4aamh9z8qy2aazt2
0x6bB84c48a071E8169aaD9fd94E8B748aC4eA3F05,terra1a9f39ewh83xhum306vsu5ryyjd30cz4wats5p5
0x039E1e57a1a1028819f7eCD11D67B49B86316E37,terra17k7pn80ym56rlvgj6s5sr37u0cu8pry5dzsw6a
0xd3B5A1b5e4D8BDC2c0aafd741D6806ea5fD5Ad89,terra1vppx6h9mz3gkqdf664ajjp90ynu7n028gl0smj
0xD691B64D4b9f0f524599168Ab3F1fEeC25A3Aa20,terra15z5muxxzf6zsges3yquprp5k93hj68yw3vmu72
0x5433225410C4b92CeCb43c92Adbf8c3Cf5193F26,terra1sjug2qa0rq996y58l56wrlyy2uyxcuxarjf2nv
0xA168B8D6e7C10800373055dab3241c6DD6945B68,terra19p9f2vmn5pfu9z0l62wuuar8fl52usz2cc3f43
0x0eaa21D9B8763FfeEc8C8Fb5e5a85EF1f79b0Be7,terra1yd3r8fdd0rnt42rqplyxmc5wn7v3pg978q20d8
0xc0a3b0c801E18c39F4a8fEABB54110E6d07bcF78,terra17rvfaqhm0a2ka3lr3qu6qh4nkvv83d5tu4npfr
0xb1108D4e2aA12948056f0D35A89751c2880204b9,terra1uhkuvcsfzjug03t23maazk776at9qgw5q0c8x4
0xA132B68B76C68588cBBeB8AB7FA095ECEbA3b4b7,terra1ggxe7klhqf8xh7p6qyv0mx4d3pccqq8qh9s4ca
0x8C1F1242bc70B1815A66E4200DA37635B4C217F6,terra1ft33eduryk8d4rqm5l2x8sv3y45tlghzu4vh6g
0xEcb25c2427EA37758954d2f43fb76630612c4Aa3,terra1uhkuvcsfzjug03t23maazk776at9qgw5q0c8x4
0x7D477EeFD6986D96F9eAe297BA74C8F1A4c37D6a,terra1uew0eweezc05t3ldzmnrynsjjy837kp6tdvaur
0xD8b014a1E0a24133016EfEbd168bf65EBB66AB5B,terra1ypdvv2hfpxjphprdredlaf2gvy6mm37w4p4q0m
0xb577dFca930c6639D0a18BfF708D2F65ed24fF0e,terra1kvmyac5ql7d74q3ukhrszvt6eds888658a98hu
0xb9465c5B8089402040a7659f97BEda4DD6Bed073,terra1kmu4pxg73lns763mkgxn054szwlyfcufhm0gn4
0x73581a242b8660Ce9BFbbc1cf555C5CCd09EB442,terra1nydhn3nzc7vn2nc00h6c2vthfrjsas3ac9azyc
0xF488288a5DC55A2AA95318a47f848F573E719250,terra1qczszm8gthsgv5v9jmg6vvpzunqtk6dyqnewzk
0x6452b5C9BfA0Ef89A4FeD1F6ad4C55d5A1D36f6D,terra16kpvz093acp7tgycdsmn7hansxhtj3kcwq2459
0x282ECd101b2164743D44CA3227b0514F8dD8d4F9,terra1n8p0zmkcfmxrm5lcse672mcuv6trvcz2gjadff
0xb74d54BB5Ad77666B1336f2F147117e782008bF3,terra1hvz8akd675z5396gvvtanwz25h6usr973d0jje
0xb5bCe5ee6C711D4f8715425635E6CDd0241D9CEB,terra1uhkuvcsfzjug03t23maazk776at9qgw5q0c8x4
0xbafb2Ecb7933aA88C0aB0e7d69F7ca6D06EEF91F,terra1l9fpakzpvzur4akregu0z25m9jd83sava7mdpr
0xE4A3110033CCd3B49895033840251fBC6a3aeF63,terra1kmdqdx4pkxjwp0mp66mx483krdtzctprc9cev9
0xEc40D60f0178c86ae5a11B1F6339B1e5a3b9a180,terra1ydzf85mfv9fq0ae5gwtwgxw98pw96nnqstxz43
0xD0Cad4F188502B2a5c952332ab421F40dD3319d3,terra19m32vy9eh5m4n9fs2nzcqt5syz0ycr4983px4k
0x983Cfce15b13D5d35784f43e168AA3BEc4728A56,terra1tj3wfa88furhdyfrdyujmhcpu9r3wfr9ywpj9c
0x816Ea0371868D631682B6050C6F18b00f85fC719,terra1k4kd5fhlt2pphrt2uulsru3up03vy7524g9yd6
0x0BF25a36E52a55fEAe3ff7938a21f25e4026fEA8,terra1ux9unexyg4ka3ujw4fstrn668vhuwd66nyfs4g
0xe9662e11d945Da0DfFF4F403e2943bAB073f7e4a,terra1x90m5fjqh5fc33alpn5uvprvrzgp6ku22rfdyq
0x168b575f24469E25ec20Bc3A6309835EEb2b64Fe,terra1jquv3ltkzlmjapt5zulyun5c7x66vlt76m7a0s
0xA9e0C85dd330F9cF9E1B1Bc68642f9957e9D5bbF,terra1lr0037kd0vqktj58g2xnlysnuqygvxc73ech40
0xc04414Af213E89527fF600877c59Ed39e16ce555,terra1078qk2hkp344jyxnckaxfhvz5ft9ue03wkzumn
0x4FB1BFaf158ad0A933f8f0d7cEdBfA13418Fc7c0,terra10x48xks2pnj67hwrj8y9q0jzenc7zg2ppevhwr
0xc738A9698C59995D6Bc911d9788EeE083EBd4798,terra18pncljutf68zjsse6g043p4m0tjswefyl0eh02
0x7F957B7Fe99dd0D515A2283420b6D8702Be2ff18,terra1ay6xgxwkyq92h3kqmrlw2wgf8pyylv3jd2p0ax
0xE89f34b4abC3f5Ba781ccc228186D8a67Bb8A2A0,terra1qcwaagfps92mfykapf3xn8t29038s0vtl038lf
0xAcEd11AF0EC256Bf68D759d3Fd98b5Ad6f746047,terra1x0mgsm2ry0amepgyp572kvp68gdhfmxpk9awhz
0x2168577Af945529fc223E3a2f6D55Cc68D8f294A,terra1gq98wfnkk6vl4gxjzuevzcxn8yx97ygruezqvy
0x30549f8BB63c7b4b387bA31f7Ed7b6Ef840fa1a5,terra1cj6t2yjdggcx48chrvn09escs05rl222jk86fl
0xD5f47B56D30aB0734ae6Fc37E07B04d98d119Ae8,terra1x9hw2xqekfpanrz5m67r5zylu0vtmwddsuz7fm
0x5Dfc35f07Cd39E1434a4B326EDd60Fb43eBc14e2,terra1yc3rmlxfpy5njkhtexzgxvemwcp5xj2l06dcey
0x2489882b0235dd680Fb13d5AE886B10AD9d4AB54,terra1t4hscy8ysmk8cpsp47nsrn9r66j6nurrav97cd
0x963DBD876178A2Eb9e7F41B7c3f045556CC7eB53,terra150gk90jzzsgwue8rekwzs9shaf354zkzz9r298
0xB6D64D2dF0F5943a686DE38cf3611986041A7494,terra1cvq4kgaks8njhlvh992p78xnvpylztg2y6zjt6
0x984602368d6f5A2247EF37F488951b7569c25a2F,terra1s4jsve4ufhgwq5suhhux6zveqglgdx0c9syr2y
0xF72D358a0E275128c538f68396e40b3849079771,terra1hherjjnmanhyu33z3yvnh7yl7xzutaeuxw3d8u
0x770BCcB2F326435AFda99871890f5cC23B2f6058,terra1zhjhuuu9zuptqyrjwc6vlspx8l9n5vq7rl9j6l
0x341cAFA35aB6f39a0779Ad74c117e8ec470bc119,terra18lg86nck8npkfkf0k6t5ala9tvyv2uva8jfmeg
0xBDd3216fc579d179DeAc230B0Fe8cF330f6AEF45,terra1ag449xakvj78hvyzws42l7gf9tzen8fk0sv7cc
0x147b728E0eB4d04CF99681901cA110C3f016E1B9,terra1v4c4nt9m69ygmrdk3p3z0ndfa9u2ygklc3s3a2
0x19dC90Da000aCc9a72222197f2615a4C798f7BB8,terra10wdndlpzd8qh76vv7n7qszrs72gn9dn96xg6yk
0x8363eefEd9eA3699a016ED59A2f6877DC4557486,terra197pgehsls6n2tpvk5hrj59vmpulnpwkwl5m8k6
0x006D26d1B640DBB9F9783Ce0fdD700639ADb11A3,terra1wduenzqjf9nxr20smhmcwjkeun5a4u7ef5q04t
0xaA4117CFd347b901D616608d9A48e55caF4e48AB,terra1q87m4p2zel5e5dad30amssg60c4lay8jcesv3n
0xC53d1C0D645a07FD025f74418e2aC2d706a73c87,terra1dh5wmxfu5yw89da0rnk8ua07gwan3rshrc6xne
0x7B76ADF47b09F09e1107A1235E513724168d95f0,terra180hpgfdn9e42jmm82t7rt3wzes00s9t83rhfu4
0xB7E8cEA5f825B7629E7Bab43DAdD553942DE7BFf,terra1nrncetene29ljruc2aqt8z84q079q2yy0qxunc
0x7FeC9ed4FD76621BA8Bff928DC4AE2C3c8Afac82,terra1vdwzp9vvdzg0sunx4m6sr7vx8m723vzsxvpufr
0x9543c41F7ec5d88F27b4Fa6F9cB19B5d611ff91A,terra1f94sqx8q6pqww0y0sr75l2lu3jarmmexx8t5rr
0xcf6ABc719b7C6Daa65908D3B40289DBED703a58e,terra1rjth8srcg76hvjq7lkrr0z47ktyqf88xqltpps
0x57F9AA310070Ae3C7c7Ef5AaD1eE8d8a72D78E3f,terra10zt9vefyhf2tzc28f3lwj0etp3ngy5nxm4qdfu
0xd965DF40e1C607197e51bc8D9ae6eB649C17E709,terra1u22na87almf80lwxfcjtz88xfdh3dpv8qarz7d
0x9222f3fAD317Af2Fa4Feb4176BF3cfCE798080a6,terra164xryjrxp0uzf7d2nzqyv03pplw8uxu7u2mvpz
0xFc64410a03b205b995a9101f99a55026D8F1f1da,terra1yyg2x4jauwgx2w4js9c3te44pvfemuzzk24ece
0xfB78d902f231aDb839928A1A76c36b9a289eD230,terra1z6vwexv688qqum29aqlyhpdwm6q8cv6zm7e030
0xfD8786ffF2C12091CC75CEAd543bE4A561C619Dd,terra1zn9sq520xya9egsav8s9lmhepn8lq8r6ztxdtm
0xa01EA2c9ef393Beb78410Df3529E60de330a9807,terra1j8c62n6l72mvlggtv76su6hdy65jzfznp7appw
0x1a98347250498531758446aC22E605dceb46005c,terra1ty4kdz46js0n2cyr020zyml879ztgwgzsjffnw
0x5F688dC8371D9071725fc6835E654B3085Ab049D,terra1ak2pw69tr9vkdtfp5mvjf4qlly9lagc7nkhwvc
0xF3f78c87E63C73D9F2fF96D6d45678730c29cb84,terra17lu3wf47nfz4eupwrv7zx5mw9p6p2alnm7fzc2
0xF63bCbC8FbB56951f6Cf7cDAcE61c2154cAc8B1F,terra1ax6aea82c6wvl366kygpuanwel3xqzy3ntgzmx
0x484cC7b3DF840dbCcA28322Dda3E2D5647964548,terra1txg2e53uszk95ntymnmgsjeht478xq3y5cndyl
0xF2670EbDD32EAd8c41BC627cbB95f3e9c4a68393,terra1rp0s5q5frssfk3klj8rza5emh6u86v22gj9y3h
0x9b47a47237670EcBbC04ba88F6f4D0ce754453b1,terra1sqp7r7xue8kwxl09nhsf48r4qx83gr672w3v4e
0x36Ade8Bf25b8a5f2635E04D3af76F1CF85892B18,terra1n85wmg43jyjhytwvdvrd3al8qw7klq7x5qalal
0x3733899d84F50A5afE89514b97f2D7C71ed4E99E,terra1fmd27dewtny73tmlapv9zvstry8ejt5vsnn3n7
0xdBD542D08A52c1A379Cf6627e6CfAA571Bdc7B5C,terra1lgsx8nzj0yd2wr6aw787y6v5wdhzavkd0ea8p8
0x44bE98130fB63eb3a068929EF3a102f15c2e6159,terra18m9y3dvlj98zcc0am69xq0tgjzp8nt8uf5e2st
0x4537cdaf67c664cE6677b49d3065670E26cD3b05,terra1a2hqp4g0edqtjwgll499arrgvygzxqssxmxvz5
0xF150864E56E0d4d3B78a3304Aa9958da87260078,terra1q4y4mm3fv54798dtm5xt4xjnmc8twca4luz7vp
0x217bc33c0Cb3d56afFFBAb22dbA019e5c2c6a2AB,terra1vlyt80wtzlcuchawfvuq0nd8qlf8eeywf56usn
0x75aFCA17418b030e64C189b9F2dd8a5E82889DCf,terra123kt2lzq65e0ysw7yt4ldthk23uwe57t48hlel
0x7AbAd6A57689266B8628DA93F1F4fBd10399dA1c,terra1wf44e9yjfp6w0syged05vr2uyj0y48r9vxwc77
0x41868a8e43BFd46F2dB34bd38DF81cF87e318cff,terra1csxnqdpe6ujuemlk22cxry78wthzfjvt7w89jq
0xCf9ff6dc75e74468816CDDf478B832071e9D1426,terra1ta3htd0nlj92ulz9at7pw0pywrphke9h7vvyhg
0x271fA7Be0D9e9925CC88baD7c4993D0B3761dc0c,terra16k7jvn78w45w4nupf5y0djcwt2sklal4cdxwnx
0x967b53D39d24D3f047e18511edcD7DcA4aaf8273,terra1s8lexs278fw2czun9g7r5e8laxxjyyaksxe539
0x08ceaA18578ddE9435a0Fb358C0E19b7f68fd749,terra1zerz8fq8t9ug832vv4seccqw057s9qrnzrffdv
0x0E69Cd42894C9105a883317b0A9f9fe53A0D20ae,terra1d8m25fn8sydxeml29hvcldqt0sj4s36hmlpdck
0x0B3bfB65881AaA5fAFd8488F3c1E15ED12D8a3Bb,terra1hue2tpcx83kp23nndszmrf6j0dgw0yclc2y2sx
,terra1cn70sru5ut70rgr8trq9q7kjqtkcuefsgfzg36
,terra1xnn3xn766t0hruu8upf857r6kt2c9g802dnwgu
,terra17adptq2l84h67d047jze5dsr66s20uj859skf7
,terra1dvchczauds9fl6tg2y9ktgyt2pwe23w8qp6qwa
,terra1jwdd5gvvt0zy6py65nzvp78zlmmevk4yqwwj8m
,terra1x9hkm6w8xlz3rz53p6dqt54f6ate668nr63jec
,terra1v2e4mwds3ulstvg0kewkmy2hhcva3a3w2kudmh
,terra178r6x4uvf6lr4f6ye62u98tjd0px2zafrn33ca
,terra12uf37flueua6tenr2lnwayhmk94m3cvkaalh8g
,terra1n6aq6mjmnzvkhelphy9wzvlh47srgz5k42lw23
,terra1zgrfqccd0fhmxqdculaggs873n0nur2qxhsmle
,terra1nx3un7dlvlw2rknau43zmtwpeml0s72peeg8re
,terra1fcar8jqx6n7vvx7zx3s7p8cpr3p4ezx2v7ywsr
,terra1sjsl4xr4kyldqrcvdt9p9tz3qzeh0cx4rvcccl
,terra1p820tpnuv3h0jya9y5ju9v3l5vc27l9fp5jtvv
,terra1umzu5h2y37af5f4t93km8zh34a7uru5h8sfv4k
,terra1wz6prwtda4tjfvqzw2m5n765w8303l04qv0azs
,terra15srcea8u8ks226tvyuaxcmvp3usa8fefgvnmel
,terra1xerg0lxm24v7h34xezq08z4lj4h7duzwny4g0p
,terra10l6wdxmqftt2e37zzfj9egpnne7j4p665tyrkx
,terra1akdzf47xdrmlhlxrtfvcdazr7cjqa0atdd6lsd
,terra1wag5t6d5v5reqsrhmevqu8htmvwmfwnnjtt427
,terra1k5jqtxvtv8h496cyfw4j7htn3dz947sfw48u9u
,terra1gew69nk8zr24jm3ddkgt3kx4fgzgxwvxg0qs4m
,terra14040pmrq2m82wf5mq70l8h78mutpkupne7wt74
,terra1a4jflz3eqk5upfuvnwwxcrlhukgvmu0f6sgygd
,terra1tv6gt5ldkdfz8sgtcrssmvydhy29r9wm8afwhc
,terra1knk9pjs6unmtrdw0lxdv40ec03d3mhlt95r0pa
,terra1uv3pw00ylnr8xyxd24cze2ge82pdxtky43gc2m
,terra1z3s4r63vs6azjazdzelfdfwus0nvq0ctxvk6vl
,terra1fpmqhqsyzhks2z3xy97rxy5cq9k5num9gjdnx2
,terra1fzhtzxkkf3pehmqutf8s6nqm7ux2fpdeh5ck7q
,terra1ul9sc3nutd655y32dcqnnlq5tes2a8acs9j4rk
,terra1kq4v9llsynkvv76t39xqhsvelmjkpnu26llej2
,terra176svmez80r6xgh5std2v4gcrmxh26wxu0tuhc2
,terra18xe77cuksxc4u9e43kmp87nvfnr92qlsj6u3kp
,terra1hjdrzs6g4u8c23sz8rsxsshkuncpr28sy5g6rw
,terra1xyw37evtvqlnacku9j3jdlducqykyjyg72fxky
,terra1qmmr6dxlwk9f86sn2q9ap9ddlk0zcm5kj07zps
,terra1m6dk3lnjm9pz78fcglw5vetqpexkrku594vwrw
,terra16tn8w9s6ld4a2gddm56ttt70afc5kre4v67l5g
,terra1n8zfknsayqt4f73njqzr58up3wn2swgfxq00u2
,terra1w8dg04c6uldssyywz25et5fy9dq3mxwn3vhpgg
,terra15qvr5wztfx262p9465hlvcjdvrcyglcf4t86rz
,terra14rchvunfgaszwlw3tr860vt3g2eketu4k3rjhk
,terra1gqxwyparddd8mwgk8cdnwf3plr20fxwc0vxs6r
,terra18j6uz4ev4hlg5pnuuvvj85w422hu7n0vt43p8l
,terra1g5h30wzyptms6zpct8j4ctj0f5ymuqjlf75m9u
,terra1exrhpn4x8kfj29r7zj04e9856cdrj3lm5at209
,terra1pwm8838sg9m7awlf226s6mrsxm9pflmzsunudk
,terra10ha4qpyu9um99rhmdhnv3ayvx79twlsyxxq838
,terra1jtxedlcwexq2sl05ez6v2cqa4tas7qlnxw9tw3
,terra1xxcasez94e7ntxcpcullx889pzdmykck5gujp4
,terra1vavvgmkwmy4745ryy06grn3qzymsspjwpnd7rk
,terra1ye4jxapkdr4da2g7qmm9qsudrscmq7mcvsjgnt
,terra1z7s7v38uq97s40jzmecy76l3mp8g683j00rntp
,terra1ayu286k9qwdwmlpa5me0nvpx55qz8mc6fd839p
,terra1d5stky9a68ykjarm6vd5z95n0zk5x4w5jtsfmr
,terra1756z0qztwzw6j546s3adx9m6kg3a33h88k40eu
,terra1k48ewshjjfhdulj5fgkegj0wy8n53rkq62rzjq
,terra1qehd4sgyep6ua0892jfgf4jha5vtg68dn6dxy7
,terra17ypy2zf4qgxqfclz0lcfegep8llk5dxqascyk0
,terra1w2hyr9lrdxztyajsm8yj387easn92un2c7ulm7
,terra1dza8vl55q2ksyy934p9pk0wlnk8m4mvux2sr3y
,terra1xwqln37wjyg5qj9v8y5d2qaqc9n4nppek3mexr
,terra1fm9xe2cgcs507u3n04wqr43av9fu2l4xqphdjt
,terra14tq40t5894zds4n95d68uv89uxfckruzaph5kf
,terra19c5438hqqmralycgrrtyfxemrnchfs782g5y9a
,terra1z8xgp8pnsg5dah57nxk3cxp50qjtk8t2nmhj6c
,terra1vwxaf7y6pqvrm4dnc8muf84886pk0k5cqrq0kt
,terra1l5ueft9awlf4kvdewpxykkscmqa0t7yc0y764h
,terra147953hnk6w6r8jwt0s8cpfvuk8avsz33xnccpe
,terra1p2jvx26ks0476ddlgc00prexadzmce58ur32mt
,terra1cpdutmqjsu8fxsd36g85sw730pjslstl5r2hrz
,terra13axpek29tf89gg2fn04vr6t7kgqkxz60mjn0vh
,terra16mqe8j9s0j5z46gckssat8dqd8wavscrrx700x
,terra1t6pn7pw8vl2l3f69xnj8gssmwjwe29pnycruyl
,terra1rzzw44nynvnx5cxf5l5qjhn7d5xanzt4w89cde
,terra192xzxk0775qxu9w4y8tqladgx3grxjnep9kae4
,terra1rp0s5q5frssfk3klj8rza5emh6u86v22gj9y3h
,terra1nxvyz207vtme8n5nu5ddsk8va448efvk5vead2
,terra1s9mnzepnew3wq3altkxe23hdtfk7r536e4u7e2
,terra1qpcj6se9kcugsy35cyj2tnxe3au5e8c962negr
,terra1t66s5zk0qsfwhpvu9e849xctgaetqp7wqvruk9
,terra1ghl8t42dd8ketcjuugn0eaghy4akyyae0yctjl
,terra1ma2d4yckz3hmw2rkwz09k989njnrx4aygvcmfz
,terra18f35d2e9hmg23daal2wp0dxk95924l96nrrj9y
,terra163pnyz822jnwf8qlzredy7phs20ph2524n0qqf
,terra13ekp7t9jdmfhhk00656jtxchmp4qwcsh8cdr3z
,terra1me0syzhzvctpm7nsmhwwv00pd9vr5ewwhmv49w
,terra144vvzhe3nax8lusdlrqysdr3jzklhgqhg54zhz
,terra1nteakz4zzulqzurj00npjquzykvlejvpdftth0
,terra14fychhy07qjak6gjycrfh82gelykcem9hafelz
,terra1jp7lz2nzhykdwplh2k39pgkmt8qdup7wh9lmgy
,terra109melm05ljvf84tf08x4yrf56mfklvsvtg6p8d
,terra1w5p904ugl30q7g9jyzqp9wf7fw0anytdu78efv
,terra1dlx6v623c62raq3j5pgpwgxlpzkzqm08z0evps
,terra1srjzzxejpsq6clxv4kd33zxg2pmy94gtszqeg3
,terra1dhqcjg06t9q6hpf99a0624jfnghuww7u9rqa42
,terra1jlf5ezcwzdvnm0wmxe44l5khnpgsm5u7dvm46q
,terra1lvzg9gkssq784a4xtzkrg20qqgwzptcm8tasm6
,terra10d8ejlcwmnkxgx76v4xkm92jdv00jw8ehsmfkr
,terra18pfrq33fjxajdv4c4dj7vdrpmsg4sdnap5y4zt
,terra1m0ny6huglwnedntjzh9m9ccd07dc4nrq0z67j4
,terra1max9ttz9y62uhljqqhn2z5mslf6qzzqxla8jyf
,terra14yqzed5yt7zt727ptczx2qqzcrz0ewg97rsra6
,terra1pjzslwxw3qagwnycttt8ml3r0dmu8hfud028v8
,terra1k5qdx3luefuck5sa40udmdaezgtwu2wvu55az5
,terra17cpcaeku2e6ltylzmz7qu208yl4rn97gyjs0yx
,terra1749ga672sen7ed75v6sdr7jhxgwd3d00unac2q
,terra18h4dgehygy6asxckhuya3vhxnxl5xrtsc23w7c
,terra1udhsqqpv253ags0exwkutgq5kq7yllsq05fx8s
,terra15d8a0z0w3ctt2j5amufxxuw40rc3hdhqvgl2qc
,terra1y6accxx84mdpuqmhd6z4jhu5hcu7fhpaxsvc8s
,terra1yte30ftqr0g6n7dtdpk78c6w93vckzcud52m8e
,terra159l0ftglx6xggcg6eep4qgr6d3zc7ln7cgw8nt
,terra1nrxnqxrs30p9wlspvacrag3sdjru5rqd2x90ra
,terra19zphjlk8y2fdzj4wdczyrjktrrnjqlpfqdhe2g
,terra14eju0v9rtuee74vre0dsvlelyzexdnxazcvlgk
,terra1w2vjr5fp4pf5lczlttcp2zm6nskdzt4cyqvqyn
,terra14e5dlcdcdmvkrq30pf4m7cvaqx5nn8r04v2hed
,terra19sp2ma0ecukw58sqv04w07y83hmyr809w7rvdt
,terra1t04vg90gvwm2kcs09vpg4syx05230g63v06plr
,terra1gcjynehyw009szdcj58v6ahs0ukd47u57mkcsr
,terra1vy0nqje03md92uzw7y7wya0ykz7kctrsulszgn
,terra1lsexhjgfcdj2p3hejaz527vcenhp7udu93d7gr
,terra1vzsgdqk7y0737raj935vesfmrkgnk8upmsfng5
,terra1uva8psrkzzv8rhuqjaftwt969hjm0qa9zfh8rc
,terra1na5ckmhu2399p863la7vtytqzr8cq4s0q5t294
,terra1tut0t05a0xrsz7963dlnxlxtjxs8pqp0zkkyte
,terra1w647m05vhr70yj7ykquxajwfpqsmhyn6hzft7k
,terra14yn6dcjx3cxnwmw6rmlnwm6nhchfrq2r0vzjjp
,terra15rh6ap9srkmwfv7wsnfec5ly7ct5fkc62907l3
,terra1pmp5pn4jdaew0e2tryz373e8whac40esazmcma
,terra1aa7jfzlefu6r7ehzykqw4sdu447jvqjz8tac5m
,terra1ytnrt2xxaff2zzr0n3zw3rfp7r0myn2cpfmzda
,terra1axhs4duj7cup2u03u4x0u7tumeszac849glnjn
,terra1plu3ph8nfruaczn5e4ztepdhzx9r6yzzrw0f7r
,terra1dkdlhq4age0qpl5xcmdxmgnsddwd6wv77h3s47
,terra1cxryvyja4d90a0jlt2m4zt79x0cpsge8xu7lzl
,terra1h2jq85yyh5lg2f5ps8wkpkvsnd3s7k5d05356p
,terra1tpun0k5rz6z4nwfu5d8hecuhllskwpk7z4s66z
,terra1h8ywsf4ywm3jq70yhf748gvh9eg7d22t5m9lu2
,terra1m5hvsmpvw7lam5y5h6czk7rw8erm3ux625rhyj
,terra1w7rqrsrjtzqd5xlm8thvvgf4ad0l6k2rh9tdfq
,terra1sae88kk58m27ujz5hyhqk488y44tt9wmh0mu42
,terra1ya0vrv0zgjhc7exszu76fxj9gvsuuzedla4rq8
,terra102239yegezy33fzws2uf8l7jugw32906pkr75d
,terra10wplfy00x7y53hk4wt8hmwgntdpj9hz6g4m6nt
,terra1zqdmks3d5v4kw9da0ma968lydhk3m9vyp8ejn4
,terra1p4vx62rmf4q87ukaenwg8gtyfgu7svcq35ymlt
,terra1szn293uxpqvlzwl8y8esa7r6wrd3rywpllanlr
,terra1qcwaagfps92mfykapf3xn8t29038s0vtl038lf
,terra1xwrlfht5mmfufg5wydam5q5qm28536rxczrjkg
,terra1hqy783jxs55udzgyskltmpz0xr63683xed7znw
,terra1zgl8rwtwpn0pyz5h3at4apgcg8vmgfy5gjt6r4
,terra1k2k924fef9u0lwrf03jgrqwcagusdrwftewlap
,terra186s428gvefq23dchz2cq0avwt9fze86hsfa03m
,terra1qgmcnm22juk68xmt6sxj550ecd4r8yuz5h9q7g
,terra18lcvgkruku24nuuw7wdwkzq7q0nak7ljz4zpc9
,terra12nwm3ljz02sz7l5d07gj8qp5cgw26sdqr7dwlz
,terra1gy4dm23wxusglsuxfldnttx3ex927ssc6l4egp
,terra1ccr8vd65xtnce6n02t4gj9fhj3g3aapy6tqye9
,terra1hgdfh7w3jsczw0phektgl8272g2jvrn8z3d9sm
,terra15keagfursjal7dh34nhs7rcepnnpkl858ykjxe
,terra1n7nu9sjvf29td7wnx4rfj5glf00qpa2fjmsa09
,terra1am7un7jfpgjlths0wv0526czlzw39hs69v9ex5
,terra16p2qnewxrfthhylpr3wjgamy0ag2dhmwphfkks
,terra10jl54wrnge3h94rm52eyjgsqelv7t30c7gpf9r
,terra1g2wucht608curvxesl47vnqrv8a8w23ns0pvqc
,terra12lks5pegfhmwhymemrttry324jmknmemnxtxn7
,terra1j4qv9eppfm9k0tzweud6f6jcgndjkg2mkmfk0l
,terra1q8rsz9es64rv20a4h7zzp7ns504tsgkum36paa
,terra1097w5jp2lwr4f3sey326zyjc78nfmlprlpwk2w
,terra1cnxg0jwm76dga62maranemxq4c6xj6qwa2nmq8
,terra1u5cm5haln28u2dgnkdgh97c00nnq78cqmumhtj
,terra17zyy8zqej7wu5qgm83d52twfpc0aev5z5k59ah
,terra14m5fwf47tc2qsklj5039mkzq2nlgmwkgdw3l4p
,terra1grm2gwjqanc473czs33vjdqe0ynqmmy54dfezs
,terra1p2lxjxkfdpg0mccsf4xdatpaxdyu7eenesnshk
,terra1rscyt97yl7lsevclv96323m5q3p3w5vsdjvnde
,terra1zt8zcyc8r3mlyl32lpn59xzeq7gwpgaaa2nr0n
,terra1xsjd4cyfj574fx57myyrmj892wkm78nqknfuax
,terra17d9lqjaemk8w4vazzqfw0m474xcstsdzwm4q5k
,terra1x90m5fjqh5fc33alpn5uvprvrzgp6ku22rfdyq
,terra1zy86xsp9nt9twl3l4h6zskwzxcg70d53hlc2q5
,terra1glgklavugfzc6enhysuf2tmnmf7ayagxywaeas
,terra15e438v6hq70vvea0d8mmnc2wjyjku5qacsrcjv
,terra104pfjjkzw4mrjrgf58d5jk7prqkw6pjqxmxvdq
,terra1xqwelhp2hwvkx9sg4hg8qj7q5cusczwle7z6sz
,terra1cml5mmsdh674943psrlvsxva3qxrc4qapq8t33
,terra195yy7speygqtrwurqm5tdpufz58zrmpfv58a9m
,terra1qmz26x2fleu4mrrl9ny2yg0aljrrr7vcfu8hch
,terra1k63jqgy9st8eg944e2grrt3rftaa99vchgzy2g
,terra12364v885s0kze5xjurhegnmcef45fmet5e76nx
,terra12nvsm8hwjclh60gdtv3gdgxfe58sdhx25uqyfr
,terra1qczszm8gthsgv5v9jmg6vvpzunqtk6dyqnewzk
,terra1hzsem376yhguf406dq7qj0a203a6y2527zmkpd
,terra1zq7era2695z8gte72lanfwxhj9878an7dlz6yz
,terra16lxptz9esaugrs4aq9cap7ph6s0rfnv3z95k3y
,terra1suumnhy5j9qk9y4egvvdlc4am4n5m4ajlt5tqn
,terra1vy4v3w5nru697z30m4khz8exn0eulyha8x6ehv
,terra1xascemvtsctqkmagjjgycj5qhg3uqhse6v8z2t
,terra1p3k5w0h7yz2lf5eep73deqfe6ltyaxscej4t2t
,terra19d0e7fpj9uklawh8khvutwk6qtfhlfznw00dm4
,terra1qy0w4l8asakyq050a27fs9f4tvlw37lt88dquf
,terra10407l0em22sxemyazl8gzw9v7a6rdx99tswuw6
,terra1tz3cx6kmar7svgh9fc9em6ds9rvkd0hlpl4wn3
,terra16pjscg50nwnyp5j50e2f75lqvf65sv2mnvdndj
,terra16y7wu8a80fp6q607fz8jvuqhjaav0andqcl9mj
,terra1ef28hkry0c949eczmqsgx50xqtt8zx5060gtvy
,terra104dxfjr3sha99gyuj3ugsm0fv3kjd79d2adgqt
,terra129cfgpm40vvaeccrqh43rk8vzjsg77c2nwgree
,terra139eylrdwv624pkkw4fsn79rnnmp93nvetrmw7l
,terra15cmgw6j39nv2kppekfxkh4upqxd889emn3329u
,terra1pr75hvxwpmy2yddeytuunck59lpzdn2jgvdl7n
,terra1s9j3kh79spuwdy2k7nlq7keuv0amana7h48x27
,terra1sq5jyj0kpyjcflwjq4ea27d4vretgh6pzyfdy0
,terra1zvvcq2cmxr49yuv4950a3s6j09y953v2yms8q4
,terra12chg7fexj3ugpet0qges6qa38rqw92ljs978ue
,terra1v6navuzmslut6yctgchc38hu9lnn9n6hxa5ze7
,terra1k25qyl9w0s6ty0xu884j00s8zvecvf3dcc2cat
,terra1558khzz3xjs5tl33ej08p67s9pwm6j7d2r3vyy
,terra1vr2fna36ywmsn2558ugpx00v8cvlsmhwzyrc4a
,terra1g2dvgeh2kstqg5d5fszkenha7c3x7arv2uqj8u
,terra192k02d72glhe8rah7tegf8tlk8hhgez5qafl2v
,terra15fthsc07y3fkfjz43wjjplzn3gzdkfrst59kvd
,terra1wdvyvfcr9ay703qhvl6qzdx2ucqf8je4unvul0
,terra12wlr5ftke6heewsuvqj38zkfjht0xec5s34427
,terra17luytjpxa8nx7n8aau8rd43ja7md67l8lt5jxr
,terra1r9u3xpvl976yp940acc5nyydy5jc6jeut622r3
,terra1spqqnyz8kcv9n9efkfkd39xuahsr366xztc7se
,terra1cu4j3a5e70cj9jgmnjtss6a9vnrqpnqp3wrfqw
,terra1phf6nd4qc72f86u2556wztnmu3css92ak2r7z9
,terra1hwxjg3upqtwv29jsttzq2t7hqq0yjm6ey7nza7
,terra1nkk9kxcjuwpm62035slkwg4yu20xxt63ncazps
,terra18x8gf06nde98pkuytpgtjp2vkrvr9dvdeu6fqc
,terra1w7qpvxrcx74xytegzd38aemn6jrulvpfj6gc9m
,terra139lwwh5r6j30a3v8l8ns4tdvxksrys8u5ly2hh
,terra106093zs3rm4q46hcwtaa3waqfx64lerszf4qff
,terra1qtttufhfs2nsl7gla3rdgjh7aqdhvus3pszam8
,terra1pslrl84xakptxhuqz25uz7p8tlfnkasrcp9wll
,terra100sac2v7dtsrmcr8mtuy7r6untsx4h8ryly67v
,terra13pxygkmqzm0jvtwxdyg7lc86jgmhs9kctsk8gv
,terra1jqu0r20mktd0gnutwdknd4s5864y760ydyx9hm
,terra1etzhm0xuzve6k2crzvx2ar64ww3et9gz2xut23
,terra1n5g7s9svjctf3ulgrx6rqhfpln0gd9v9pfprvs
,terra1zhphrc3436ffu67ah6677c03pcacmdy9tpcy92
,terra1dlj3u68lusmag8mldpx4nnu0yevm5vhzanquk6
,terra195vjy5dkw47h6vqmsnzv3mc6fgxzel00sgprey
,terra16vvf2w0r8agplsrrgma5n5cvuuenu0zmjdaxht
,terra19r9vztpnv0qw5rv9jne9mdf682lr8malntjzjr
,terra194fkgwded3ts2ygkhhasq4spqpdj828rj2qmh8
,terra178r6x4uvf6lr4f6ye62u98tjd0px2zafrn33ca
,terra1ndl0nwepa2ggn7hfwsvcf752p8zjed0pzps0f4
,terra105366vajqnfpx0e9a8573ehus9daw7yr7kn5qq
,terra1tzjrwzf0afze6tcrdsg6tycvj4w43dh3wdtymw
,terra1k4du5rcvvtswpm4hr6k4xa2t2lqkj4s80uqpcr
,terra10payqxzwxqw2nx7yv8upy36qt9g77kgjs0nhs3
,terra1kd2kl9562du3grlamzn9czvh0zwzgelcaqhelt
,terra1zu4g4ctr3nn0wtdh782h6zywya72rqs2h4yzey
,terra16de54tgcmuk5wymv4q6l82h8dpd3k56fg5xn7c
,terra1jv0j5sc4szzpqeezrttvzwhpp3yq7aydjhv3eu
,terra1tt6c69vx92lkaxz42ty0awtau9rvdmljflyzsu
,terra1da0lyjwlfp4655ky7zwu6r6783p8x3sdex0kdp
,terra1eup9dxhl3xccfhc4eyddze96rzz89pjarzdurg
,terra1dvvwtgzuqeqww77wej3k4kuh54rehj08nch5wn
,terra1aeak93c75yhdeaw4j2kar3zzklm67dpxdlnmk5
,terra1fz7slaqx7lzc84zgmx0ck2snnmkl4vu97l2g5u
,terra1hykkzvga0qrt5hpzxkkmc2t5a474au60sjz658
,terra1c676kdnzrk42m9tvgevggfaj297ecg0k4jx90y
,terra1q3hekgwms5m5rhsu8u7v9stxfv55pkxe4dm2z5
,terra1trlvnatgvzdevs0hjap4ezj4femddwpjzf3w0h
,terra1sgyr6zpcnvpx74m7gpw72vqnxu0a4thpmxmfxr
,terra1c834m3vjrc9qwpzs4lyar4k4z456ugt6dmulew
,terra1twwtt53c0epk3hx6f0vp3zp05rpzyhcrvpu7hn
,terra1yr5u3nsjuj2hthtdaxsc6lha499y0wgy4mgee9
,terra1m8axzv2hcpyhnln22d6rump27ghqv2e6m20tw0
,terra1twaf6jkaw20f25a2gdzqq85klsrfkfc2ut5ns9
,terra1evnqp7fzvxt5znqe9kc4xfhtc2nnfjzrz3fldx
,terra10gkcsphgk4a4d97f9v6znr7zqcmrycq4rwzyr6
,terra13wnxqnz2zvksus5tx6w2xxvd0fam9dm6veusa9
,terra1ta3htd0nlj92ulz9at7pw0pywrphke9h7vvyhg
,terra1f7xu63lktgmntyd797uf7y74zkme3hnx9y5v05
,terra1a96fhrvajfcs05fj66d8z9qg3zd8zttmyex70l
,terra1ta6xg59vjllnmyn3rateh3sr3f8xyj6hpmkz4f
,terra135lzsasn9kfuyycd9yrclhykh7kfm7pqj37fss
,terra1uxqtc9sa7s08uudcl5njrxvtptemlvlkmrsvnd
,terra1ugd0gcusmnh6s5ul7r69schkdgzf9lkdacuyue
,terra1a9zuee9vsqaxl4wtnenp4cmlrn25cgc0lx30ur
,terra1002jjypw2vkchf9jy4v80x3m9wd87lwgax5gkj
,terra1hyrjdcm74yhufyuxw9lergq7s364rangdwelmu
,terra13s3d0ueqyyddmnwxwfuqtypfds8fxlv76l6fp9
,terra1a0pst55jk806a3aca93lgmfzdr05hk667xmqh6
,terra186p9aqxgk48nz995f3pzrq7xt7ht0y48qzca74
,terra1qrcqmyjqwnh2aee06jaa6azwv0y6xxrqv9d86g
,terra13rzuyuysxsk7hafh3ueu6v7l2lcz0hxg4scdgs
,terra18p9pj8yc9ua0mwcr83nudcs0vzjwjz4f942rh8
,terra1q0ekwlr9r323f027dln4yznfgf6a56p5ed4w6f
,terra146mtjp6q5vcfwg4n5tdmc7yap5q83m2ru7ylxx
,terra187uvap9vac6usvdtjz98gadu36zt6453vlknt0
,terra15pkfk4a9m6s72ukarlru865gynmmjgs6xg83uh
,terra1wljs794krgtceq88wljlpaq5xksw5x3vvdx404
,terra14dh5lrxh4shjcjs7dns2hpdzpcy9jgv9u24hkc`
