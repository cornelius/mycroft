package main

import (
  "fmt"
  "os"
  "encoding/json"
  "path/filepath"
  "io/ioutil"
)

type Space struct {
  dir string
  admins map[string]User
  users map[string]User
  persistent bool
}

func (space Space) AdminFilePath() string {
  return filepath.Join(space.dir, "admins.json")
}

func (space Space) UserFilePath() string {
  return filepath.Join(space.dir, "users.json")
}

func (space Space) DataDirPath() string {
  return filepath.Join(space.dir, "data")
}

func (space Space) TokenDirPath() string {
  return filepath.Join(space.dir, "tokens")
}

func (space Space) WriteAdmins() {
  if space.persistent {
    jsonString, _ := json.Marshal(space.admins)
    err := ioutil.WriteFile(space.AdminFilePath(), jsonString, 0600)
    if err != nil {
      fmt.Printf("Error writing admins: %v\n", err.Error())
    }
  }
}

func (space Space) WriteUsers() {
  if space.persistent {
    jsonString, _ := json.Marshal(space.users)
    err := ioutil.WriteFile(space.UserFilePath(), jsonString, 0600)
    if err != nil {
      fmt.Printf("Error writing users: %v\n", err.Error())
    }
  }
}

func (space Space) ReadAdmins() {
  jsonString, err := ioutil.ReadFile(space.AdminFilePath())
  if err != nil {
    fmt.Printf("Error reading admins: %v\n", err.Error())
    os.Exit(1)
  }
  err = json.Unmarshal(jsonString, &space.admins)
  if err != nil {
    fmt.Printf("Error unmarshaling admin JSON: %v\n", err.Error())
  }
}

func (space Space) ReadUsers() {
  jsonString, err := ioutil.ReadFile(space.UserFilePath())
  if err != nil {
    if os.IsNotExist(err) {
      return
    } else {
      fmt.Printf("Error reading users: %v\n", err.Error())
      os.Exit(1)
    }
  }
  err = json.Unmarshal(jsonString, &space.users)
  if err != nil {
    fmt.Printf("Error unmarshaling user JSON: %v\n", err.Error())
  }
}

func (space Space) CreateBucket() (string, error) {
  bucketId := CreateRandomString(10)

  bucketDirPath := filepath.Join(space.DataDirPath(), bucketId)
  err := os.MkdirAll(bucketDirPath, 0700)

  return bucketId, err
}

func (space Space) DeleteBucket(bucketId string) (error) {
  bucketDirPath := filepath.Join(space.DataDirPath(), bucketId)
  err := os.RemoveAll(bucketDirPath)

  return err
}

func (space Space) HasBucket(bucketId string) (error) {
  bucketDirPath := filepath.Join(space.DataDirPath(), bucketId)
  _, err := os.Stat(bucketDirPath)
  return err
}

func (space Space) CreateToken() (string, error) {
  token := CreateRandomString(16)

  err := os.MkdirAll(space.TokenDirPath(), 0700)
  if err != nil {
    return token, err
  }

  tokenFilePath := filepath.Join(space.TokenDirPath(), token)
  err = ioutil.WriteFile(tokenFilePath, []byte(""), 0600)

  return token, err
}

func (space Space) RemoveToken(token string) error {
  return os.Remove(filepath.Join(space.TokenDirPath(), token))
}
