package main

import (
  "code.google.com/p/go.crypto/bcrypt"
)

type User struct {
  PasswordHash string `json:"password_hash"`
}

func createUser() (id string, passwordString string, admin User) {
  id = CreateRandomString(10)
  passwordString = CreateRandomString(10)
  password := []byte(passwordString)
  passwordHash, _ := bcrypt.GenerateFromPassword(password, 10)
  admin = User{string(passwordHash)}
  return
}
