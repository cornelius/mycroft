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
  if admin.password != expected_password {
    t.Errorf("createAdmin() = '_, %v', want '%v'", admin.password, expected_password)
  }
}
