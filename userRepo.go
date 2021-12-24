package main

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type UserRepo struct {
	Users []*User
}

func NewUserRepo() *UserRepo {
	repo := UserRepo{}
	p1, _ := bcrypt.GenerateFromPassword([]byte("200303"), bcrypt.DefaultCost)
	p2, _ := bcrypt.GenerateFromPassword([]byte("20030307"), bcrypt.DefaultCost)
	repo.Users = []*User{
		&User{
			ID:       1,
			Email:    "s57111702@gmail.com",
			Name:     "Vadim",
			Password: string(p1),
		},
		&User{
			ID:       2,
			Email:    "s57111702@gmail.ua",
			Name:     "Mary",
			Password: string(p2),
		},
	}
	return &repo
}

func (u *UserRepo) GetByEmail(email string) (*User, error) {
	for _, user := range u.Users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, errors.New("User not found")
}

func (u *UserRepo) GetById(Id int) (*User, error) {
	for _, user := range u.Users {
		if user.ID == Id {
			return user, nil
		}
	}
	return nil, errors.New("User not found")
}
