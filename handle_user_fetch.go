package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

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
		saveUser(user)
	}

	delete(user, "iphash")
	registrations := DbSelect("select * from users_registrations where user_id = $1", user.Get("id"))
	baseAllocation, snapshotUsers := snapshot(currentIdoName, currentIdoRaising, false)
	userInSnapshot := false
	userAllocation := float64(0)
	for _, u := range snapshotUsers {
		if u.Get("user_id") == user.Get("id") {
			userInSnapshot = true
			userAllocation = u.GetFloat("possibleAllocation")
			break
		}
	}
	RenderJson(w, 200, J{
		"user":           user,
		"registrations":  registrations,
		"baseAllocation": baseAllocation,
		"userInSnapshot": userInSnapshot,
		"userAllocation": userAllocation,
	})
}

func fetchUpdateUserAmounts(user J) {
	// Ethereum
	if address := user.Get("address_ethereum"); address != "" {
		data, err := contractTiers.Pack("userInfoAmounts", common.HexToAddress(address))
		Check(err)
		var resultStr string
		err = clientEthereum.Call(&resultStr, "eth_call", map[string]interface{}{
			"from": ADDRESS_ZERO,
			"to":   contractTiersAddressEthereum,
			"data": hexutil.Bytes(data),
		}, "latest")
		if err == nil {
			result, err := contractTiers.Unpack("userInfoAmounts", hexutil.MustDecode(resultStr))
			Check(err)
			amountb := result[4].([]*big.Int)[0]
			amountb.Div(amountb, big.NewInt(1000000000))
			amountb.Div(amountb, big.NewInt(1000000000))
			amountb.Div(amountb, big.NewInt(10))
			amountb.Add(amountb, big.NewInt(1))
			amountb.Mul(amountb, big.NewInt(10))
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
		b64query = base64.URLEncoding.EncodeToString([]byte(`{"thorstarter_terra_boost":{"terra_address":"` + address + `"}}`))
		result, err = httpGet(`https://fcd.terra.dev/terra/wasm/v1beta1/contracts/terra10pxt36lyy6rhsumw7j8lahwvwrre7fxrfktgjl/store?query_msg=` + b64query)
		if err == nil {
			state := result.(map[string]interface{})["query_result"].(string)
			balance := big.NewInt(int64(MustParseInt(state)))
			balance.Div(balance, big.NewInt(1000000))
			user["amount_mintdao"] = int(balance.Int64())
		} else {
			log.Println("fetchUpdateUserAmounts: terra mintdao:", address, err)
		}
	}

	// Fantom
	if address := user.Get("address_fantom"); address != "" {
		amount := big.NewInt(0)

		{
			data, err := contractTiersSimple.Pack("userInfos", common.HexToAddress(address))
			Check(err)
			var resultStr string
			err = clientFantom.Call(&resultStr, "eth_call", map[string]interface{}{
				"from": ADDRESS_ZERO,
				"to":   contractTiersAddressFantom,
				"data": hexutil.Bytes(data),
			}, "latest")
			if err == nil {
				result, err := contractTiersSimple.Unpack("userInfos", hexutil.MustDecode(resultStr))
				Check(err)
				amountb := result[0].(*big.Int)
				amountb.Div(amountb, big.NewInt(1000000000))
				amountb.Div(amountb, big.NewInt(1000000000))
				amount.Add(amount, amountb)
			} else {
				log.Println("fetchUpdateUserAmounts: fantom:", address, err)
			}
		}

		{
			data, err := contractForge.Pack("getUserInfo", common.HexToAddress(address))
			Check(err)
			var resultStr string
			err = clientFantom.Call(&resultStr, "eth_call", map[string]interface{}{
				"from": ADDRESS_ZERO,
				"to":   contractForgeFantom,
				"data": hexutil.Bytes(data),
			}, "latest")
			if err == nil {
				result, err := contractForge.Unpack("getUserInfo", hexutil.MustDecode(resultStr))
				Check(err)
				amountb := result[0].(*big.Int)
				amountb.Div(amountb, big.NewInt(1000000000))
				amountb.Div(amountb, big.NewInt(1000000000))
				amount.Add(amount, amountb)
			} else {
				log.Println("fetchUpdateUserAmounts: fantom:", address, err)
			}
		}

		user["amount_fantom"] = int(amount.Int64())
	}

	// TC LP
	tcAddress := user.Get("address_ethereum")
	if tcAddress == "" {
		tcAddress = user.Get("address_fantom")
	}

  // MintDAO Shields NFT
	if address := tcAddress; address != "" {
		b64query := base64.URLEncoding.EncodeToString([]byte(`{"thorstarter_eth_boost":{"eth_address":"` + address + `"}}`))
		result, err := httpGet(`https://fcd.terra.dev/terra/wasm/v1beta1/contracts/terra10pxt36lyy6rhsumw7j8lahwvwrre7fxrfktgjl/store?query_msg=` + b64query)
		if err == nil {
			state := result.(map[string]interface{})["query_result"].(string)
			balance := big.NewInt(int64(MustParseInt(state)))
			balance.Div(balance, big.NewInt(1000000))
			user["amount_mintdao"] = int(balance.Int64())
		} else {
			log.Println("fetchUpdateUserAmounts: fantom mintdao:", address, err)
		}
	}

	if address := tcAddress; address != "" {
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
			log.Println("fetchUpdateUserAmounts: tclp:", address, err)
			/*
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
			*/
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

func saveUser(user J) {
	user["updated_at"] = time.Now()
	db.MustExec(
		`insert into users (id, address_ethereum, address_terra, address_fantom, address_polygon, amount_ethereum, amount_terra, amount_fantom, amount_polygon, amount_tclp, amount_forge, amount_mintdao, iphash, updated_at) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) on conflict (id) do update set address_ethereum = $2, address_terra = $3, address_fantom = $4, address_polygon = $5, amount_ethereum = $6, amount_terra = $7, amount_fantom = $8, amount_polygon = $9, amount_tclp = $10, amount_forge = $11, amount_mintdao = $12, iphash = $13, updated_at = $14`,
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
		user.GetInt("amount_mintdao"),
		user.Get("iphash"),
		user.GetTime("updated_at"),
	)
}
