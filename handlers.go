package main

import (
  "fmt"
  "net/http"
  "github.com/gorilla/mux"
  "os"
  "encoding/json"
  "strings"
  "encoding/base64"
  "code.google.com/p/go.crypto/bcrypt"
  "errors"
  "path/filepath"
  "io/ioutil"
)

func rootHandler(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, "hello\n")
}

func adminRegisterHandler(pin string, space Space) VarsHandler {
  fn := func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    if len(space.admins) > 0 {
      http.Error(w, "Admin client already registered", 400)
      return
    }
    received_pin := vars["pin"]
    if received_pin == pin {
      id, password, admin := createUser()
      space.admins[id] = admin
      space.WriteAdmins()
      json_map := map[string]string{
        "admin_id": id,
        "password": password,
      }
      json_string, _ := json.Marshal(json_map)
      fmt.Fprintf(w, "%v\n", string(json_string))
      diary.RegisteredAdminClient(received_pin)
    } else {
      fmt.Printf("Registering admin client with wrong pin %v. Exiting.\n", received_pin)
      os.Exit(1)
    }
  }
  return fn
}

func userRegisterHandler(space Space) VarsHandler {
  fn := func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    token := vars["token"]
    tokenFilePath := filepath.Join(space.TokenDirPath(), token)
    _, err := ioutil.ReadFile(tokenFilePath)
    if err != nil {
      if os.IsNotExist(err) {
        http.Error(w, "Invalid token", 404)
      } else {
        http.Error(w, err.Error(), 500)
      }
      return
    }

    id, password, admin := createUser()
    space.users[id] = admin
    space.WriteUsers()
    space.RemoveToken(token)
    json_map := map[string]string{
      "user_id": id,
      "user_password": password,
    }
    json_string, _ := json.Marshal(json_map)
    fmt.Fprintf(w, "%v\n", string(json_string))
    diary.RegisteredUserClient(token)
  }
  return fn
}

func adminsAsJson(admins map[string]User, users map[string]User) (string, error) {
  json_hash := make(map[string][]string)

  json_array1 := []string{}
  for id := range admins {
    json_array1 = append(json_array1, id)
  }
  json_hash["admins"] = json_array1

  json_array2 := []string{}
  for id := range users {
    json_array2 = append(json_array2, id)
  }
  json_hash["users"] = json_array2

  json, err := json.Marshal(json_hash)

  return string(json[:]), err
}

func adminClients(admins map[string]User, users map[string]User) handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    json, err := adminsAsJson(admins, users)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    } else {
      fmt.Fprintf(w, "%v\n", json)
    }
  }
  return fn
}

func adminListBuckets(space Space) handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    buckets, err := ioutil.ReadDir(space.DataDirPath())
    if err != nil {
      if os.IsNotExist(err) {
        fmt.Fprintf(w, "[]\n")
        return
      } else {
        http.Error(w, err.Error(), 500)
        return
      }
    }
    bucketList := []string{}
    for i := range buckets {
      bucketList = append(bucketList, buckets[i].Name())
    }
    json, err := json.Marshal(bucketList)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }
    fmt.Fprintf(w, "%v\n", string(json[:]))
  }
  return fn
}

func adminListTokens(space Space) handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    tokens, err := ioutil.ReadDir(space.TokenDirPath())
    if err != nil {
      if os.IsNotExist(err) {
        fmt.Fprintf(w, "[]\n")
        return
      } else {
        http.Error(w, err.Error(), 500)
        return
      }
    }
    tokenList := []string{}
    for i := range tokens {
      tokenList = append(tokenList, tokens[i].Name())
    }
    json, err := json.Marshal(tokenList)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }
    fmt.Fprintf(w, "%v\n", string(json[:]))
  }
  return fn
}

func ParseBasicAuthHeader(header http.Header) (username string, password string, err error) {
  authHeader, ok := header["Authorization"]
  if !ok {
    return "", "", errors.New("Authorizaton header missing")
  }

  auth := strings.SplitN(authHeader[0], " ", 2)

  if len(auth) != 2 || auth[0] != "Basic" {
    return "", "", errors.New("Bad Syntax")
  }

  payload, _ := base64.StdEncoding.DecodeString(auth[1])
  pair := strings.SplitN(string(payload), ":", 2)

  if len(pair) != 2 {
    return pair[0], "", nil
  }

  return pair[0], pair[1], nil
}

type handler func(w http.ResponseWriter, r *http.Request)

func BasicAuth(pass handler, lookup func(string) (User, bool)) handler {
  return func(w http.ResponseWriter, r *http.Request) {
    username, password, err := ParseBasicAuthHeader(r.Header)

    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }

    if password == "" || !ValidatePassword(username, password, lookup) {
      http.Error(w, "Authorization failed", http.StatusUnauthorized)
      return
    }

    pass(w, r)
  }
}

func BasicAuthVars(pass VarsHandler, lookup func(string) (User, bool)) VarsHandler {
  return func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    username, password, err := ParseBasicAuthHeader(r.Header)

    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }

    if password == "" || !ValidatePassword(username, password, lookup) {
      http.Error(w, "Authorization failed", http.StatusUnauthorized)
      return
    }

    pass(w, r, vars)
  }
}

func ValidatePassword(username, password string, lookup func(string) (User, bool)) bool {
  if user, ok := lookup(username); ok {
    err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
    if err == nil {
      return true
    }
  }
  return false
}

type VarsHandler func(http.ResponseWriter, *http.Request, map[string]string)

func (h VarsHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    vars := mux.Vars(req)
    h(w, req, vars)
}

func createBucketHandler(space Space) handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    bucketId, err := space.CreateBucket()
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    json_map := make(map[string]string)
    json_map["bucket_id"] = bucketId
    json, _ := json.Marshal(json_map)

    fmt.Fprintf(w, "%v\n", string(json[:]))
    diary.CreatedBucket(bucketId)
  }
  return fn
}

func createTokenHandler(space Space) handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    token, err := space.CreateToken()
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    json_map := make(map[string]string)
    json_map["token"] = token
    json, _ := json.Marshal(json_map)

    fmt.Fprintf(w, "%v\n", string(json[:]))
    diary.CreatedToken(token)
  }
  return fn
}

type Item struct {
  ItemId string `json:"item_id"`
  ParentId string `json:"parent_id"`
  Content string `json:"content"`
}

func createItemHandler(space Space) VarsHandler {
  fn := func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    bucketId := vars["bucket_id"]

    latestIdFilePath := filepath.Join(space.DataDirPath(), bucketId, "latest_id")

    parentId := ""

    if _, err := os.Stat(latestIdFilePath); err == nil {
      latestIdContent, err := ioutil.ReadFile(latestIdFilePath)
      if err != nil {
        http.Error(w, err.Error(), 500)
        return
      }
      parentId = string(latestIdContent)
    } else {
      if !os.IsNotExist(err) {
        http.Error(w, err.Error(), 500)
        return
      }
    }


    itemId := CreateRandomString(10)

    itemFilePath := filepath.Join(space.DataDirPath(), bucketId, itemId)

    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    item := Item{itemId, parentId, string(body)}
    json_item, err := json.Marshal(item)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    err = ioutil.WriteFile(itemFilePath, json_item, 0600)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    err = ioutil.WriteFile(latestIdFilePath, []byte(itemId), 0600)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    json_map := make(map[string]string)
    json_map["item_id"] = itemId
    json_map["parent_id"] = parentId
    json, _ := json.Marshal(json_map)

    fmt.Fprintf(w, "%v\n", string(json[:]))
  }
  return fn
}

func readItem(space Space, bucketId string, itemId string) (Item, error) {
  itemFilePath := filepath.Join(space.DataDirPath(), bucketId, itemId)
  itemContent, err := ioutil.ReadFile(itemFilePath)
  if err != nil {
    return Item{}, err
  }

  var item Item
  err = json.Unmarshal(itemContent, &item)
  if err != nil {
    return Item{}, err
  }

  return item, nil
}

func readItemsHandler(space Space) VarsHandler {
  fn := func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    bucketId := vars["bucket_id"]

    latestIdFilePath := filepath.Join(space.DataDirPath(), bucketId, "latest_id")

    latestId := ""

    if _, err := os.Stat(latestIdFilePath); err != nil {
      if os.IsNotExist(err) {
        fmt.Fprintf(w, "[]\n")
        return
      } else {
        http.Error(w, err.Error(), 500)
        return
      }
    }
    latestIdContent, err := ioutil.ReadFile(latestIdFilePath)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }
    latestId = string(latestIdContent)

    items := []Item{}

    for latestId != "" {
      item, err := readItem(space, bucketId, latestId)
      if err != nil {
        http.Error(w, err.Error(), 500)
        return
      }

      items = append(items, item)

      latestId = item.ParentId
    }

    json, _ := json.Marshal(items)

    fmt.Fprintf(w, "%v\n", string(json[:]))
  }
  return fn
}