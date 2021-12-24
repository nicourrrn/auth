package main

import (
	"encoding/json"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

const liveMin = 10
const refreliveMin = 5

var AccessSecret = []byte("access_secret")
var RefreshSecret = []byte("access_secret")

func main() {
	http.HandleFunc("/login", Login)
	http.HandleFunc("/profile", Profile)
	http.HandleFunc("/refresh", Refresh)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func Refresh(w http.ResponseWriter, r *http.Request) {

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

		refreshString, err := GenerateToken(user.ID, refreliveMin, RefreshSecret)
		if err != nil {
			log.Println("error token")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := LoginResponse{
			AccessToken:  tokenString,
			RefreshToken: refreshString,
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	default:
		http.Error(w, "Only POST methid is allowed", http.StatusMethodNotAllowed)
	}
	w.WriteHeader(http.StatusOK)
}

func Profile(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":

		tokenString := GetTokenFromBearerString(r.Header.Get("Authorization"))
		claims, err := ValidateToken(tokenString, string(AccessSecret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusFailedDependency)
			return
		}
		user, err := NewUserRepo().GetById(claims.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusFailedDependency)
			return
		}
		resp := UserResponse{
			Email:    user.Email,
			Name:     user.Name,
			Password: user.Password,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	default:
		http.Error(w, "Only POST methid is allowed", http.StatusMethodNotAllowed)
	}
}
