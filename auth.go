package main

import (
  "net/http"
  "github.com/gorilla/mux"
  "strings"
  "encoding/base64"
  "code.google.com/p/go.crypto/bcrypt"
  "errors"
)

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
