package main

import (
  "testing"
  "math/rand"
)

func TestCreateUser(t *testing.T) {
  rand.Seed(42)
  expectedId := "hzwuvpx8k7"
  expectedPassword := "1b34w985zk"

  id, password, _ := createUser()

  if id != expectedId {
    t.Errorf("createUser() = '%v, _', want '%v'", id, expectedId)
  }
  if password != expectedPassword {
    t.Errorf("createUser() = '_, %v', want '%v'", password, expectedPassword)
  }
}
