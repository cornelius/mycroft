package main

import (
  "math/rand"
)

func CreateRandomString(size int) string {
  letters := "0123456789abcdefghijklmnopqrstuvwxyz"

  var bytes = make([]byte, size)
  for i := 0; i < size; i += 1 {
    bytes[i] = letters[rand.Intn(len(letters))]
  }
  return string(bytes)
}
