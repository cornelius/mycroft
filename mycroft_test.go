package main

import (
  "os"
)

func createTestSpace() Space {
  testDir := "/tmp/mycroft-test"
  os.RemoveAll(testDir)
  return Space{testDir, make(map[string]User), make(map[string]User), false}
}
