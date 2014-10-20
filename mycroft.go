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
)

type Admin struct {
  Password string `json:"password"`
}

var admins map[string]Admin

func createAdmin() (id string, admin Admin) {
  id = strconv.Itoa(rand.Intn(1000000000))
  admin = Admin{strconv.Itoa(rand.Intn(1000000000))}
  return
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, "hello")
}

func adminRegisterHandler(pid int) http.Handler {
  fn := func(w http.ResponseWriter, r *http.Request) {
    if len(admins) > 0 {
      http.Error(w, "Error: Admin client already registered", 400)
      return
    }
    received_pid := mux.Vars(r)["pid"]
    if received_pid == strconv.Itoa(pid) {
      fmt.Printf("Register admin client with pid %v\n", received_pid)
      id, admin := createAdmin()
      admins[id] = admin
      fmt.Fprintf(w, "Admin id: %v\n", id)
      fmt.Fprintf(w, "Password: %v\n", admin.Password)
    } else {
      fmt.Printf("Registering admin client with wrong pid %v. Exiting.\n", received_pid)
      os.Exit(1)
    }
  }
  return http.HandlerFunc(fn)
}

func adminsAsJson(admins map[string]Admin) (string, error) {
  json, err := json.Marshal(admins)
  return string(json[:]), err
}

func adminClients(w http.ResponseWriter, r *http.Request) {
  json, err := adminsAsJson(admins)
  if err != nil {
    http.Error(w, err.Error(), 500)
    return
  } else {
    fmt.Fprintf(w, "%v\n", json)
  }
}

func main() {
  admins = make(map[string]Admin)

  rand.Seed(time.Now().UnixNano())

  pid := rand.Intn(10000)

  port := 4735

  fmt.Printf("To register the admin client send a POST to http://<servername>:%v/admin/register/%v\n", port, pid)

  r := mux.NewRouter()
  r.HandleFunc("/", rootHandler)
  r.Handle("/admin/register/{pid}", adminRegisterHandler(pid)).Methods("POST")
  r.HandleFunc("/admin/clients", adminClients).Methods("GET")

  http.ListenAndServe(":" + strconv.Itoa(port), r)
}
