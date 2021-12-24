package main

import (
	"github.com/golang-jwt/jwt"
)

type JWTCustomClaims struct {
	ID int `json:"id"`
	jwt.StandardClaims
}

func GenerateToken(userID, lifetimeMinutes int, sectet []byte) (string, error) {
	claims := &JWTCustomClaims{
		ID: userID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(sectet)
}
