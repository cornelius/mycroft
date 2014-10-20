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
)

type Admin struct {
  PasswordHash string `json:"-"`
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

func adminRegisterHandler(pid int, admins map[string]Admin) VarsHandler {
  fn := func(w http.ResponseWriter, r *http.Request, vars map[string]string) {
    if len(admins) > 0 {
      http.Error(w, "Error: Admin client already registered", 400)
      return
    }
    received_pid := vars["pid"]
    if received_pid == strconv.Itoa(pid) {
      fmt.Printf("Register admin client with pid %v\n", received_pid)
      id, password, admin := createAdmin()
      admins[id] = admin
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
  json, err := json.Marshal(admins)
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

func main() {
  admins := make(map[string]Admin)

  rand.Seed(time.Now().UnixNano())

  pid := rand.Intn(10000)

  port := 4735

  fmt.Printf("To register the admin client send a POST to http://<servername>:%v/admin/register/%v\n", port, pid)

  router := mux.NewRouter()
  router.HandleFunc("/", rootHandler)
  router.Handle("/admin/register/{pid}", VarsHandler(adminRegisterHandler(pid, admins))).Methods("POST")
  router.HandleFunc("/admin/clients", BasicAuth(adminClients(admins), admins)).Methods("GET")

  http.ListenAndServe(":" + strconv.Itoa(port), router)
}
