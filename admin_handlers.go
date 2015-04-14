package main

import (
  "fmt"
  "net/http"
  "os"
  "encoding/json"
  "io/ioutil"
)

func adminRegisterHandler(pin string, space Space) VarsHandler {
  fn := func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    if len(space.admins) > 0 {
      http.Error(w, "Admin client already registered", 400)
      return
    }
    receivedPin := vars["pin"]
    if receivedPin == pin {
      id, password, admin := createUser()
      space.admins[id] = admin
      space.WriteAdmins()
      jsonMap := map[string]string{
        "admin_id": id,
        "password": password,
      }
      jsonString, _ := json.Marshal(jsonMap)
      fmt.Fprintf(w, "%v\n", string(jsonString))
      diary.RegisteredAdminClient(receivedPin)
    } else {
      fmt.Printf("Registering admin client with wrong pin %v. Exiting.\n", receivedPin)
      os.Exit(1)
    }
  }
  return fn
}

func adminsAsJson(admins map[string]User, users map[string]User) (string, error) {
  jsonHash := make(map[string][]string)

  jsonArray1 := []string{}
  for id := range admins {
    jsonArray1 = append(jsonArray1, id)
  }
  jsonHash["admins"] = jsonArray1

  jsonArray2 := []string{}
  for id := range users {
    jsonArray2 = append(jsonArray2, id)
  }
  jsonHash["users"] = jsonArray2

  json, err := json.Marshal(jsonHash)

  return string(json[:]), err
}

func adminListClientsHandler(admins map[string]User, users map[string]User) handler {
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

func adminListBucketsHandler(space Space) handler {
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

func adminDeleteBucketHandler(space Space) VarsHandler {
  fn := func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    bucketId := vars["bucket_id"]

    err := space.HasBucket(bucketId)
    if err != nil {
      http.Error(w, "Bucket '" + bucketId + "' does not exist", 404)
      return
    }

    err = space.DeleteBucket(bucketId)
    if err != nil {
      http.Error(w, err.Error(), 500)
      return
    }

    diary.DeletedBucket(bucketId)
  }
  return fn
}

func adminListTokensHandler(space Space) handler {
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
