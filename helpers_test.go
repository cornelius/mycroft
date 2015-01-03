package main

import (
  "testing"
  "math/rand"
)

func TestCreateRandomString(t *testing.T) {
  rand.Seed(42)

  expectedRandomString := "hzwuvpx8k7"

  randomString := CreateRandomString(10)

  if randomString != expectedRandomString {
    t.Errorf("Expected '%v', got '%v'", expectedRandomString, randomString)
  }


  expectedRandomString = "1b34w985zky6srgh"

  randomString = CreateRandomString(16)

  if randomString != expectedRandomString {
    t.Errorf("Expected '%v', got '%v'", expectedRandomString, randomString)
  }
}
