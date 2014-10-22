package main

import (
  "fmt"
  "net/http"
  "math/rand"
  "time"
  "github.com/gorilla/mux"
  "strconv"
  "os"
  "encoding/json"
  "strings"
  "encoding/base64"
  "code.google.com/p/go.crypto/bcrypt"
  "errors"
  "path/filepath"
  "io/ioutil"
)

type Admin struct {
  PasswordHash string `json:"password_hash"`
}

func createAdmin() (id string, password_string string, admin Admin) {
  id = strconv.Itoa(rand.Intn(1000000000))
  password_string = strconv.Itoa(rand.Intn(1000000000))
  password := []byte(password_string)
  passwordHash, _ := bcrypt.GenerateFromPassword(password, 10)
  admin = Admin{string(passwordHash)}
  return
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, "hello\n")
}

func adminRegisterHandler(pid int, space Space) VarsHandler {
  fn := func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    if len(space.admins) > 0 {
      http.Error(w, "Admin client already registered", 400)
      return
    }
    received_pid := vars["pid"]
    if received_pid == strconv.Itoa(pid) {
      fmt.Printf("Register admin client with pid %v\n", received_pid)
      id, password, admin := createAdmin()
      space.admins[id] = admin
      space.WriteAdmins()
      json_map := map[string]string{
        "admin_id": id,
        "password": password,
      }
      json_string, _ := json.Marshal(json_map)
      fmt.Fprintf(w, "%v\n", string(json_string))
    } else {
      fmt.Printf("Registering admin client with wrong pid %v. Exiting.\n", received_pid)
      os.Exit(1)
    }
  }
  return fn
}

func adminsAsJson(admins map[string]Admin) (string, error) {
  json_array := []string{}
  for id := range admins {
    json_array = append(json_array, id)
  }
  json, err := json.Marshal(json_array)
  return string(json[:]), err
}

func adminClients(admins map[string]Admin) handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    json, err := adminsAsJson(admins)
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
      http.Error(w, err.Error(), 500)
      return
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

func BasicAuth(pass handler, admins map[string]Admin) handler {
  return func(w http.ResponseWriter, r *http.Request) {
    username, password, err := ParseBasicAuthHeader(r.Header)

    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }

    if password == "" || !ValidatePassword(username, password, admins) {
      http.Error(w, "Authorization failed", http.StatusUnauthorized)
      return
    }

    pass(w, r)
  }
}

func BasicAuthVars(pass VarsHandler, admins map[string]Admin) VarsHandler {
  return func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    username, password, err := ParseBasicAuthHeader(r.Header)

    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }

    if password == "" || !ValidatePassword(username, password, admins) {
      http.Error(w, "Authorization failed", http.StatusUnauthorized)
      return
    }

    pass(w, r, vars)
  }
}

func ValidatePassword(username, password string, admins map[string]Admin) bool {
  if admin, ok := admins[username]; ok {
    err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password))
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

type Space struct {
  dir string
  admins map[string]Admin
  persistent bool
}

func (space Space) AdminFilePath() string {
  return filepath.Join(space.dir, "admins.json")
}

func (space Space) DataDirPath() string {
  return filepath.Join(space.dir, "data")
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

func (space Space) CreateBucket() (string, error) {
  bucketId := strconv.Itoa(rand.Intn(1000000000))

  bucketDirPath := filepath.Join(space.DataDirPath(), bucketId)
  err := os.MkdirAll(bucketDirPath, 0700)

  return bucketId, err
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


    itemId := strconv.Itoa(rand.Intn(1000000000))

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
      http.Error(w, err.Error(), 500)
      return
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


func main() {
  if len(os.Args) != 2 {
    fmt.Println("Usage: mycroft <directory>")
    os.Exit(1)
  }
  
  space := Space{os.Args[1], make(map[string]Admin), true}
  
  if _, err := os.Stat(space.AdminFilePath()); err == nil {
    space.ReadAdmins()
  } else {
    if os.IsNotExist(err) {
      err := os.MkdirAll(space.dir, 0700)
      if err != nil {
        fmt.Printf("Unable to create directory '%v'\n", space.dir)
      }
    } else {
      fmt.Printf("Error: %v\n", err.Error())
      os.Exit(1)
    }
  }
  
  rand.Seed(time.Now().UnixNano())

  pid := rand.Intn(10000)

  port := 4735

  if len(space.admins) == 0 {
    fmt.Printf("To register the admin client send a POST to http://<servername>:%v/admin/register/%v\n", port, pid)
  }

  router := mux.NewRouter()
  router.HandleFunc("/", rootHandler)
  router.Handle("/admin/register/{pid}", VarsHandler(adminRegisterHandler(pid, space))).Methods("POST")
  router.HandleFunc("/admin/clients", BasicAuth(adminClients(space.admins), space.admins)).Methods("GET")
  router.HandleFunc("/admin/buckets", BasicAuth(adminListBuckets(space), space.admins)).Methods("GET")
  router.HandleFunc("/data", BasicAuth(createBucketHandler(space), space.admins)).Methods("POST")
  router.Handle("/data/{bucket_id}", BasicAuthVars(VarsHandler(createItemHandler(space)), space.admins)).Methods("POST")
  router.Handle("/data/{bucket_id}", BasicAuthVars(VarsHandler(readItemsHandler(space)), space.admins)).Methods("GET")

  http.ListenAndServe(":" + strconv.Itoa(port), router)
}
