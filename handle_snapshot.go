package main

import (
	"fmt"
	"log"
	"net/http"
	"sort"
)

func handleAdminSnapshot(w http.ResponseWriter, r *http.Request) {
	baseAllocation, registrations := snapshot(currentIdoName, currentIdoRaising, false)
	fmt.Fprintf(w, "base %.2f registrations %d\n", baseAllocation, len(registrations))
	fmt.Fprintf(w, "address,total,tier,allocation,address_ethereum,address_terra,address_fantom\n")
	for _, r := range registrations {
		fmt.Fprintf(
			w, "%s,%d,%d,%.2f,%s,%s,%s,%s\n",
			r.Get("address"), r.GetInt("total"),
			r.GetInt("tier"), r["allocation"].(float64),
			r.Get("address_ethereum"),
			r.Get("address_terra"),
			r.Get("address_fantom"),
			r.Get("address_polygon"),
		)
	}
}
func handleAdminSnapshotUpdate(w http.ResponseWriter, r *http.Request) {
	snapshot(currentIdoName, currentIdoRaising, true)
	w.Write([]byte("ok"))
}

func snapshot(ido string, size float64, update bool) (float64, []J) {
	users := DbSelect(`select r.id, r.user_id, u.address_ethereum, u.address_terra, u.address_fantom, u.address_polygon, r.address, u.iphash, (u.amount_ethereum + u.amount_terra + u.amount_fantom + u.amount_polygon + u.amount_tclp + u.amount_forge + u.amount_mintdao) as total from users_registrations r inner join users u on u.id = r.user_id where r.ido = $1 and r.created_at <= $2 order by total desc, r.created_at`, ido, currentIdoCutoff)

	totalAllocations := float64(0)
	totalInTier := map[int]float64{}
	//tierAllocations := map[int]float64{}
	iphashes := map[string]int{}
	filteredUsers := []J{}

	for i, user := range users {
		if user.GetInt("total") == 0 {
			continue
		}
		iphashes[user.Get("iphash")]++

		// Update allocations from onchain data
		if update {
			func() {
				defer func() {
					if err := recover(); err != nil {
						log.Println("panic on user", user.Get("user_id"), err)
					}
				}()
				r := user
				us := DbSelect("select * from users where id = $1", r.Get("user_id"))
				user := us[0]
				fetchUpdateUserAmounts(user)
				saveUser(user)
				log.Println("done", i, "out of", len(users), r.Get("user_id"))
			}()
		}

		/*
		   // CHECK KYC
		   address := user.Get("address_ethereum")
		   if address == "" {
		     address = user.Get("address_terra")
		   }
		   if address == "" {
		     address = user.Get("address_fantom")
		   }
		   fmt.Println("fetching kyc", len(users), i+1)
		   kycVerified := false
		   sessions := DbSelect(`select id, session_id, verified from kyc where address = $1`, address)
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
		   if !kycVerified {
		     fmt.Println("not kyced", user.Get("user_id"))
		     continue
		   }
		   /**/

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
		user["tier"] = tier
		filteredUsers = append(filteredUsers, user)
	}

	users = filteredUsers
	sort.Slice(users, func(i, j int) bool {
		return users[i].Get("id") > users[j].Get("id")
	})

	baseAllocation := size / totalAllocations
	for _, user := range users {
		tier := user.GetInt("tier")
		allocation := float64(0)
		allocation = baseAllocation * allMultipliers[tier]
		//if baseAllocation*allMultipliers[tier] > 100 {
		user["possibleAllocation"] = allocation
		/*
			} else {
				tierAllocationCap := totalInTier[tier] * allMultipliers[tier] * baseAllocation
				if tierAllocations[tier]+100 < tierAllocationCap {
					allocation = 100
					tierAllocations[tier] += 100
				} else {
					allocation = 0
				}
				user["possibleAllocation"] = float64(100)
			}
		*/
		user["allocation"] = allocation
	}

	if baseAllocation > size {
		baseAllocation = size
	}
	return baseAllocation, users
}
