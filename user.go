package main

import (
  "code.google.com/p/go.crypto/bcrypt"
)

type User struct {
  PasswordHash string `json:"password_hash"`
}

func createUser() (id string, password_string string, admin User) {
  id = CreateRandomString(10)
  password_string = CreateRandomString(10)
  password := []byte(password_string)
  passwordHash, _ := bcrypt.GenerateFromPassword(password, 10)
  admin = User{string(passwordHash)}
  return
}
