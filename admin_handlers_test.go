package main

import (
  "testing"
  "math/rand"
  "net/http"
  "net/http/httptest"
  "sort"
  "os"
  "path/filepath"
  "bytes"
)

func TestAdminsAsJson(t *testing.T) {
  var admins map[string]User
  admins = make(map[string]User)

  adminId, _, admin := createUser()
  admin.PasswordHash = "$2a$10$36ZaYv02CY1PQxFiiuTtu.K6soUBCK330yLXwBvcaeREGfj.Bx/kC"
  admins[adminId] = admin

  var users map[string]User
  users = make(map[string]User)

  userId, _, user := createUser()
  user.PasswordHash = "$2a$10$nzocaXSZD5OE.tcdOk//furws38CGiGnpw7NZWMprvp0xwGikya/S"
  users[userId] = user

  jsonString, _ := adminsAsJson(admins, users)
  expectedJsonString := "{\"admins\":[\"" + adminId + "\"],\"users\":[\"" + userId + "\"]}"

  if jsonString != expectedJsonString {
    t.Errorf("adminsAsJson() = '%v', want '%v'", jsonString, expectedJsonString)
  }
}

func TestAdminRegister(t *testing.T) {
  rand.Seed(42)

  var buffer bytes.Buffer
  diary.out = &buffer

  expectedBody := "{\"admin_id\":\"hzwuvpx8k7\",\"password\":\"1b34w985zk\"}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/register/1234", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  f := adminRegisterHandler("1234", space)
  f(recorder, req, map[string]string{"pin":"1234"})

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}

func TestAdminClients(t *testing.T) {
  expectedBody := "{\"admins\":[\"94099423\"],\"users\":[]}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/clients", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  admins := make(map[string]User)
  admins["94099423"] = User{"xxx"}

  users := make(map[string]User)

  f := adminListClientsHandler(admins, users)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}

func TestAdminListBuckets(t *testing.T) {
  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/clients", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  admins := make(map[string]User)
  admins["94099423"] = User{"xxx"}

  space := createTestSpace()

  buckets := []string{}
  bucketId1, _ := space.CreateBucket()
  buckets = append(buckets, bucketId1)
  bucketId2, _ := space.CreateBucket()
  buckets = append(buckets, bucketId2)
  sort.Strings(buckets)

  expectedBody := "[\"" + buckets[0] + "\",\"" + buckets[1] + "\"]\n"

  f := adminListBucketsHandler(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}

func TestAdminListBucketsEmpty(t *testing.T) {
  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/buckets", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  expectedBody := "[]\n"

  f := adminListBucketsHandler(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}

func TestAdminDeleteBucket(t *testing.T) {
  rand.Seed(42)

  space := createTestSpace()

  bucketId, _ := space.CreateBucket()

  filePath := filepath.Join(space.DataDirPath(), bucketId)

  if _, err := os.Stat(filePath); err != nil {
    t.Errorf("File '%v' should exist but doesn't", filePath)
  }

  url := "http://example.com/admin/buckets/" + bucketId

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("DELETE", url, nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  f := adminDeleteBucketHandler(space)
  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expectedCode := 200
  code := recorder.Code
  if code != expectedCode {
    t.Errorf("Expected code '%v', got '%v'", expectedCode, code)
  }

  if _, err := os.Stat(filePath); err == nil {
    t.Errorf("File '%v' should not exist but does", filePath)
  }
}

func TestAdminDeleteBucketFails(t *testing.T) {
  rand.Seed(42)

  space := createTestSpace()

  bucketId := "123"

  filePath := filepath.Join(space.DataDirPath(), bucketId)

  if _, err := os.Stat(filePath); err == nil {
    t.Errorf("File '%v' should not exist but does", filePath)
  }

  url := "http://example.com/admin/buckets/" + bucketId

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("DELETE", url, nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  f := adminDeleteBucketHandler(space)
  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expectedCode := 404
  code := recorder.Code
  if code != expectedCode {
    t.Errorf("Expected code '%v', got '%v'", expectedCode, code)
  }
}

func TestAdminListTokens(t *testing.T) {
  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/tokens", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  tokens := []string{}
  token1, _ := space.CreateToken()
  tokens = append(tokens, token1)
  token2, _ := space.CreateToken()
  tokens = append(tokens, token2)
  sort.Strings(tokens)

  expectedBody := "[\"" + tokens[0] + "\",\"" + tokens[1] + "\"]\n"

  f := adminListTokensHandler(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}

func TestAdminListTokensEmpty(t *testing.T) {
  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/tokens", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  expectedBody := "[]\n"

  f := adminListTokensHandler(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}
