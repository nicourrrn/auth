package main

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

type JWTCustomClaims struct {
	jwt.StandardClaims
	ID int `json:"id"`
}

func GenerateToken(userID, lifetimeMinutes int, sectet []byte) (string, error) {
	claims := &JWTCustomClaims{
		ID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 10).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(sectet)
}

func GetTokenFromBearerString(bearerString string) string {
	if bearerString == "" {
		return ""
	}

	// parts := strings.Split(bearerString, " ")
	parts := strings.Split(bearerString, "Bearer")
	if len(parts) != 2 {
		return ""
	}

	token := strings.TrimSpace(parts[1])
	if len(token) < 1 {
		return ""
	}

	return token
}

func ValidateToken(tokenString string, secter string) (*JWTCustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(secter), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*JWTCustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("failed to parse")
	}

	return claims, nil
}
