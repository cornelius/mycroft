package main

import (
  "testing"
  "math/rand"
)

func TestCreateAdmin(t *testing.T) {
  rand.Seed(42)
  expected_id := "801072305"
  expected_password := "141734987"

  id, password, _ := createAdmin()

  if id != expected_id {
    t.Errorf("createAdmin() = '%v, _', want '%v'", id, expected_id)
  }
  if password != expected_password {
    t.Errorf("createAdmin() = '_, %v', want '%v'", password, expected_password)
  }
}

func TestAdminsAsJson(t *testing.T) {
  var admins map[string]Admin
  admins = make(map[string]Admin)

  id, _, admin := createAdmin()
  admin.PasswordHash = "$2a$10$36ZaYv02CY1PQxFiiuTtu.K6soUBCK330yLXwBvcaeREGfj.Bx/kC"
  admins[id] = admin

  json_string, _ := adminsAsJson(admins)
  expected_json_string := "{\"297281668\":{}}"

  if json_string != expected_json_string {
    t.Errorf("adminsAsJson() = '%v', want '%v'", json_string, expected_json_string)
  }
}

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
