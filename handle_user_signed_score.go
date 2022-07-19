package main

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func handleUserSignedScore(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	deadline := r.URL.Query().Get("deadline")
	refresh := r.URL.Query().Get("refresh") == "1"
	user := J{"id": SUUID(), "updated_at": time.Now().Add(-1 * time.Hour)}
	users := DbSelect("select * from users where (address_ethereum = $1 or address_fantom = $1)", address)
	if len(users) > 0 {
		user = users[0]
	} else {
		user["address_fantom"] = address
		user["address_ethereum"] = address
	}
	if refresh || time.Now().Sub(user.GetTime("updated_at")) > 30*time.Minute {
		fetchUpdateUserAmounts(user)
		saveUser(user)
	}

	totalScore := user.GetInt("amount_ethereum") +
		user.GetInt("amount_fantom") +
		user.GetInt("amount_terra") +
		user.GetInt("amount_tclp") +
		user.GetInt("amount_forge") +
		user.GetInt("amount_mintdao")
	scoreBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(scoreBytes[24:], uint64(totalScore))
	addressBytes := common.HexToAddress(address)
	deadlineBytes := make([]byte, 32)
	deadlineInt, err := strconv.ParseInt(deadline, 10, 64)
	Check(err)
	binary.BigEndian.PutUint64(deadlineBytes[24:], uint64(deadlineInt))

	values := bytes.NewBuffer(nil)
	values.Write(addressBytes.Bytes())
	values.Write(scoreBytes)
	values.Write(deadlineBytes)
	valuesBytes := crypto.Keccak256(values.Bytes())
	input := bytes.NewBufferString("\x19Ethereum Signed Message:\n")
	input.Write([]byte(strconv.Itoa(len(valuesBytes))))
	input.Write(valuesBytes)
	hash := crypto.Keccak256(input.Bytes())
	signatureBytes, err := crypto.Sign(hash, privateKey)
	Check(err)
	signatureBytes[len(signatureBytes)-1] = signatureBytes[len(signatureBytes)-1] + 27
	signature := common.Bytes2Hex(signatureBytes)
	RenderJson(w, 200, J{
		"user":      user,
		"score":     totalScore,
		"deadline":  deadlineInt,
		"signature": signature,
	})
}
