package main

import (
	"net/http"
	"strings"
)

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
	if registrationAddressType == "evm" &&
		(len(address) != 42 || !strings.HasPrefix(address, "0x")) { // Ethereum
		RenderJson(w, 400, J{"error": "invalid address"})
		return
	}
	if registrationAddressType == "terra" &&
		(len(address) != 44 || !strings.HasPrefix(address, "terra")) { // Terra
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
