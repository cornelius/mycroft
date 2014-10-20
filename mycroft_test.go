package main

import (
  "testing"
  "math/rand"
)

func TestCreateAdmin(t *testing.T) {
  rand.Seed(42)
  expected_id := "801072305"
  expected_password := "141734987"

  id, admin := createAdmin()

  if id != expected_id {
    t.Errorf("createAdmin() = '%v, _', want '%v'", id, expected_id)
  }
  if admin.Password != expected_password {
    t.Errorf("createAdmin() = '_, %v', want '%v'", admin.Password, expected_password)
  }
}

func TestAdminsAsJson(t *testing.T) {
  var admins map[string]Admin
  admins = make(map[string]Admin)

  id, admin := createAdmin()
  admins[id] = admin

  json_string, _ := adminsAsJson(admins)
  expected_json_string := "{\"297281668\":{\"password\":\"448434750\"}}"

  if json_string != expected_json_string {
    t.Errorf("adminsAsJson() = '%v', want '%v'", json_string, expected_json_string)
  }
}
