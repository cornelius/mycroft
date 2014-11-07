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

type User struct {
  PasswordHash string `json:"password_hash"`
}

func createUser() (id string, password_string string, admin User) {
  id = strconv.Itoa(rand.Intn(1000000000))
  password_string = strconv.Itoa(rand.Intn(1000000000))
  password := []byte(password_string)
  passwordHash, _ := bcrypt.GenerateFromPassword(password, 10)
  admin = User{string(passwordHash)}
  return
}

func mergeUsers(users1 map[string]User, users2 map[string]User) map[string]User {
  allUsers := make(map[string]User)

  for key, value := range users1 {
    allUsers[key] = value
  }
  for key, value := range users2 {
    allUsers[key] = value
  }

  return allUsers
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
      id, password, admin := createUser()
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

    fmt.Printf("Register user client with token %v\n", token)
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

func BasicAuth(pass handler, users map[string]User) handler {
  return func(w http.ResponseWriter, r *http.Request) {
    username, password, err := ParseBasicAuthHeader(r.Header)

    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }

    if password == "" || !ValidatePassword(username, password, users) {
      http.Error(w, "Authorization failed", http.StatusUnauthorized)
      return
    }

    pass(w, r)
  }
}

func BasicAuthVars(pass VarsHandler, users map[string]User) VarsHandler {
  return func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    username, password, err := ParseBasicAuthHeader(r.Header)

    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }

    if password == "" || !ValidatePassword(username, password, users) {
      http.Error(w, "Authorization failed", http.StatusUnauthorized)
      return
    }

    pass(w, r, vars)
  }
}

func ValidatePassword(username, password string, users map[string]User) bool {
  if admin, ok := users[username]; ok {
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
  bucketId := strconv.Itoa(rand.Intn(1000000000))

  bucketDirPath := filepath.Join(space.DataDirPath(), bucketId)
  err := os.MkdirAll(bucketDirPath, 0700)

  return bucketId, err
}

func (space Space) CreateToken() (string, error) {
  token := strconv.Itoa(rand.Intn(10000000000000))

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
  
  space := Space{os.Args[1], make(map[string]User), make(map[string]User), true}
  
  if _, err := os.Stat(space.AdminFilePath()); err == nil {
    space.ReadAdmins()
    space.ReadUsers()
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
  router.HandleFunc("/admin/clients", BasicAuth(adminClients(space.admins, space.users), space.admins)).Methods("GET")
  router.HandleFunc("/admin/buckets", BasicAuth(adminListBuckets(space), space.admins)).Methods("GET")
  router.HandleFunc("/data", BasicAuth(createBucketHandler(space), space.users)).Methods("POST")
  router.Handle("/data/{bucket_id}", BasicAuthVars(VarsHandler(createItemHandler(space)), space.users)).Methods("POST")
  router.Handle("/data/{bucket_id}", BasicAuthVars(VarsHandler(readItemsHandler(space)), space.users)).Methods("GET")
  router.HandleFunc("/tokens", BasicAuth(createTokenHandler(space), mergeUsers(space.admins, space.users))).Methods("POST")
  router.HandleFunc("/admin/tokens", BasicAuth(adminListTokens(space), space.admins)).Methods("GET")
  router.Handle("/register/{token}", VarsHandler(userRegisterHandler(space))).Methods("POST")

  http.ListenAndServe(":" + strconv.Itoa(port), router)
}
