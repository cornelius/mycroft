package main

import (
  "fmt"
  "net/http"
  "os"
  "encoding/json"
  "path/filepath"
  "io/ioutil"
)

type handler func(w http.ResponseWriter, r *http.Request)

func rootHandler(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, "hello\n")
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
    jsonMap := map[string]string{
      "user_id": id,
      "user_password": password,
    }
    jsonString, _ := json.Marshal(jsonMap)
    fmt.Fprintf(w, "%v\n", string(jsonString))
    diary.RegisteredUserClient(token)
  }
  return fn
}

func createBucketHandler(space Space) handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    bucketId, err := space.CreateBucket()
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    jsonMap := make(map[string]string)
    jsonMap["bucket_id"] = bucketId
    json, _ := json.Marshal(jsonMap)

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

    jsonMap := make(map[string]string)
    jsonMap["token"] = token
    json, _ := json.Marshal(jsonMap)

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
    jsonItem, err := json.Marshal(item)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    err = ioutil.WriteFile(itemFilePath, jsonItem, 0600)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    err = ioutil.WriteFile(latestIdFilePath, []byte(itemId), 0600)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    jsonMap := make(map[string]string)
    jsonMap["item_id"] = itemId
    jsonMap["parent_id"] = parentId
    json, _ := json.Marshal(jsonMap)

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

func pingHandler() handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "{\"ping\":\"pong\"}\n")
  }
  return fn
}
