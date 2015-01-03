package main

import (
  "testing"
  "math/rand"
)

func TestCreateUser(t *testing.T) {
  rand.Seed(42)
  expected_id := "hzwuvpx8k7"
  expected_password := "1b34w985zk"

  id, password, _ := createUser()

  if id != expected_id {
    t.Errorf("createUser() = '%v, _', want '%v'", id, expected_id)
  }
  if password != expected_password {
    t.Errorf("createUser() = '_, %v', want '%v'", password, expected_password)
  }
}
