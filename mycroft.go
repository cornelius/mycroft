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
      http.Error(w, "Error: Admin client already registered", 400)
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

func createBucketHandler(space Space) handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    bucketId := strconv.Itoa(rand.Intn(1000000000))

    bucketDirPath := filepath.Join(space.DataDirPath(), bucketId)
    err := os.MkdirAll(bucketDirPath, 0700)
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
  router.HandleFunc("/data", BasicAuth(createBucketHandler(space), space.admins)).Methods("POST")
  
  http.ListenAndServe(":" + strconv.Itoa(port), router)
}
