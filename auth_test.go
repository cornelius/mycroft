package main

import (
  "testing"
  "code.google.com/p/go.crypto/bcrypt"
)

func TestBasicAuth(t *testing.T) {
  header2 := make(map[string][]string)
  header2["User-Agent"] = []string{"curl/7.32.0"}
  header2["Accept"] = []string{"*/*"}
  header2["Authorization"] = []string{"Basic eHh4Onl5eQ=="}

  username, password, err := ParseBasicAuthHeader(header2)

  if username != "xxx" {
    t.Errorf("ParseBasicAuthHeader(%v), expected username '%v', got '%v'", header2, "xxx", username)
  }
  if password != "yyy" {
    t.Errorf("ParseBasicAuthHeader(%v), expected password '%v', got '%v'", header2, "yyy", password)
  }
  if err != nil {
    t.Errorf("ParseBasicAuthHeader(%v), didn't expect error, got '%v'", header2, err)
  }

  header1 := make(map[string][]string)

  _, _, err = ParseBasicAuthHeader(header1)

  if err == nil {
    t.Errorf("ParseBasicAuthHeader(%v), expected error", header1)
  }
}

func TestValidatePassword(t *testing.T) {
  user := "somename"
  password := "somepassword"

  users := make(map[string]User)
  hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
  users[user] = User{string(hash)}

  lookup := func(username string) (User, bool) {
    user, ok := users[username]
    return user, ok
  }

  valid := ValidatePassword(user, password, lookup)
  if !valid {
    t.Errorf("ValidatePassword('%v', '%v', '%v') didn't match, but should", user, password, users)
  }
  valid = ValidatePassword(user, "wrongpassword", lookup)
  if valid {
    t.Errorf("ValidatePassword('%v', 'wrongpassword', '%v') matched, but shouldn't", user, users)
  }

  user2 := "anothername"
  password2 := "anotherpassword"

  valid = ValidatePassword(user2, password2, lookup)
  if valid {
    t.Errorf("ValidatePassword('%v', '%v', '%v') matched, but shouldn't", user2, password2, users)
  }

  hash, _ = bcrypt.GenerateFromPassword([]byte(password2), 10)
  users[user2] = User{string(hash)}

  valid = ValidatePassword(user2, password2, lookup)
  if !valid {
    t.Errorf("ValidatePassword('%v', '%v', '%v') didn't match, but should", user2, password2, users)
  }
}
