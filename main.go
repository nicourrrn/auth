package main

import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

const liveMin = 10

var AccessSecret = []byte("access_secret")

func main() {
	http.HandleFunc("/login", Login)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func Login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		req := new(LoginRequest)
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, err := NewUserRepo().GetByEmail(req.Email)
		if err != nil {
			http.Error(w, "invalid....", http.StatusUnauthorized)
			return
		}

		if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			http.Error(w, "invalid....", http.StatusUnauthorized)
			return
		}
		// r, _ := json.Marshal(map[string]interface{}{
		// 	"ID":    user.ID,
		// 	"name":  user.Name,
		// 	"email": user.Email,
		// })
		// w.Write(r)

		tokenString, err := GenerateToken(user.ID, liveMin, AccessSecret)
		if err != nil {
			log.Println("error token")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := LoginResponse{
			AccessToken: tokenString,
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	default:
		http.Error(w, "Only POST methid is allowed", http.StatusMethodNotAllowed)
	}
	w.WriteHeader(http.StatusOK)
}
