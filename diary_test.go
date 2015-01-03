package main

import (
  "testing"
  "bytes"
)

func TestDiary(t *testing.T) {
  var buffer bytes.Buffer
  diary.out = &buffer

  diary.RegisteredAdminClient("1234")

  expectedString := "Registered admin client with pin 1234\n"
  if buffer.String() != expectedString {
    t.Errorf("Expected '%v', got '%v'", expectedString, buffer.String())
  }
}
