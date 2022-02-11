package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func handleKyc(w http.ResponseWriter, r *http.Request) {
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
