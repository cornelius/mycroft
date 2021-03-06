package main

import (
  "fmt"
  "net/http"
  "math/rand"
  "time"
  "github.com/gorilla/mux"
  "github.com/gorilla/handlers"
  "strconv"
  "os"
  "flag"
)

func main() {
  rand.Seed(time.Now().UnixNano())

  diary.out = os.Stdout

  var logPath string
  var pin string
  var showVersion bool

  flag.StringVar(&logPath, "logfile", "mycroft-access.log", "Path to log file")
  flag.StringVar(&pin, "pin", CreateRandomString(4), "PIN for initial admin resgistration")
  flag.BoolVar(&showVersion, "version", false, "Show version and exit")

  flag.Parse()

  if showVersion {
    fmt.Printf("Version: %v\n", Version)
    os.Exit(0)
  }

  if flag.NArg() != 1 {
    fmt.Println("Usage: mycroft <directory>")
    os.Exit(1)
  }
  
  space := Space{flag.Arg(0), make(map[string]User), make(map[string]User), true}
  
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
  
  port := 4735

  if len(space.admins) == 0 {
    fmt.Printf("To register the admin client send a POST to http://<servername>:%v/admin/register/%v\n", port, pin)
  }

  lookupUser := func(username string) (User, bool) {
    user, ok := space.users[username]
    return user, ok
  }

  lookupAdmin := func(username string) (User, bool) {
    user, ok := space.admins[username]
    return user, ok
  }

  lookupAny := func(username string) (User, bool) {
    user, ok := space.users[username]
    if ok {
      return user, ok
    }
    user, ok = space.admins[username]
    return user, ok
  }

  router := mux.NewRouter()
  router.HandleFunc("/", rootHandler)
  router.Handle("/admin/register/{pin}", VarsHandler(adminRegisterHandler(pin, space))).Methods("POST")
  router.HandleFunc("/admin/clients", BasicAuth(adminListClientsHandler(space.admins, space.users), lookupAdmin)).Methods("GET")
  router.HandleFunc("/admin/buckets", BasicAuth(adminListBucketsHandler(space), lookupAdmin)).Methods("GET")
  router.Handle("/admin/buckets/{bucket_id}", BasicAuthVars(VarsHandler(adminDeleteBucketHandler(space)), lookupAdmin)).Methods("DELETE")
  router.HandleFunc("/data", BasicAuth(createBucketHandler(space), lookupUser)).Methods("POST")
  router.Handle("/data/{bucket_id}", BasicAuthVars(VarsHandler(createItemHandler(space)), lookupUser)).Methods("POST")
  router.Handle("/data/{bucket_id}", BasicAuthVars(VarsHandler(readItemsHandler(space)), lookupUser)).Methods("GET")
  router.HandleFunc("/tokens", BasicAuth(createTokenHandler(space), lookupAny)).Methods("POST")
  router.HandleFunc("/admin/tokens", BasicAuth(adminListTokensHandler(space), lookupAdmin)).Methods("GET")
  router.Handle("/register/{token}", VarsHandler(userRegisterHandler(space))).Methods("POST")
  router.HandleFunc("/ping", BasicAuth(pingHandler(), lookupUser)).Methods("GET")

  logFile, err := os.OpenFile(logPath, os.O_WRONLY | os.O_CREATE | os.O_APPEND, 0700)
  if err != nil {
    panic(err)
  }
  defer logFile.Close()

  http.ListenAndServe(":" + strconv.Itoa(port), handlers.CombinedLoggingHandler(logFile, router))
}
