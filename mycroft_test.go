package main

import (
  "testing"
  "math/rand"
  "net/http"
  "net/http/httptest"
  "sort"
  "os"
  "strings"
  "io/ioutil"
  "path/filepath"
  "code.google.com/p/go.crypto/bcrypt"
)

func createTestSpace() Space {
  testDir := "/tmp/mycroft-test"
  os.RemoveAll(testDir)
  return Space{testDir, make(map[string]User), make(map[string]User), false}
}

func TestCreateUser(t *testing.T) {
  rand.Seed(42)
  expected_id := "801072305"
  expected_password := "141734987"

  id, password, _ := createUser()

  if id != expected_id {
    t.Errorf("createUser() = '%v, _', want '%v'", id, expected_id)
  }
  if password != expected_password {
    t.Errorf("createUser() = '_, %v', want '%v'", password, expected_password)
  }
}

func TestAdminsAsJson(t *testing.T) {
  var admins map[string]User
  admins = make(map[string]User)

  id, _, admin := createUser()
  admin.PasswordHash = "$2a$10$36ZaYv02CY1PQxFiiuTtu.K6soUBCK330yLXwBvcaeREGfj.Bx/kC"
  admins[id] = admin

  var users map[string]User
  users = make(map[string]User)

  id, _, user := createUser()
  user.PasswordHash = "$2a$10$nzocaXSZD5OE.tcdOk//furws38CGiGnpw7NZWMprvp0xwGikya/S"
  users[id] = user

  json_string, _ := adminsAsJson(admins, users)
  expected_json_string := "{\"admins\":[\"297281668\"],\"users\":[\"94099423\"]}"

  if json_string != expected_json_string {
    t.Errorf("adminsAsJson() = '%v', want '%v'", json_string, expected_json_string)
  }
}

func TestReadUsers(t *testing.T) {
  space := createTestSpace()

  // Should not fail
  space.ReadUsers()
}

func TestBasicAuth(t *testing.T) {
  header2 := make(map[string][]string)
  header2["User-Agent"] = []string{"curl/7.32.0"}
  header2["Accept"] = []string{"*/*"}
  header2["Authorization"] = []string{"Basic eHh4Onl5eQ=="}

  username, password, err := ParseBasicAuthHeader(header2)

  if username != "xxx" {
    t.Errorf("ParseBasicAuthHeader(%v), expected username '%v', got '%v'", header2, "xxx", username)
  }
  if password != "yyy" {
    t.Errorf("ParseBasicAuthHeader(%v), expected password '%v', got '%v'", header2, "yyy", password)
  }
  if err != nil {
    t.Errorf("ParseBasicAuthHeader(%v), didn't expect error, got '%v'", header2, err)
  }

  header1 := make(map[string][]string)

  _, _, err = ParseBasicAuthHeader(header1)

  if err == nil {
    t.Errorf("ParseBasicAuthHeader(%v), expected error", header1)
  }
}

func TestAdminRoot(t *testing.T) {
  expected_body := "hello\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  rootHandler(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestAdminRegister(t *testing.T) {
  rand.Seed(42)

  expected_body := "{\"admin_id\":\"801072305\",\"password\":\"141734987\"}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/register/1234", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  f := adminRegisterHandler(1234, space)
  f(recorder, req, map[string]string{"pid":"1234"})

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestAdminClients(t *testing.T) {
  expected_body := "{\"admins\":[\"94099423\"],\"users\":[]}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/clients", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  admins := make(map[string]User)
  admins["94099423"] = User{"xxx"}

  users := make(map[string]User)

  f := adminClients(admins, users)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestCreateBucket(t *testing.T) {
  rand.Seed(42)

  expected_body := "{\"bucket_id\":\"801072305\"}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("POST", "http://example.com/data", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  f := createBucketHandler(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
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

  expected_body := "[\"" + buckets[0] + "\",\"" + buckets[1] + "\"]\n"

  f := adminListBuckets(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestAdminListBucketsEmpty(t *testing.T) {
  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/buckets", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  expected_body := "[]\n"

  f := adminListBuckets(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestWriteAndReadItems(t *testing.T) {
  rand.Seed(42)

  space := createTestSpace()

  bucketId, _ := space.CreateBucket()

  url := "http://example.com/data/" + bucketId

  
  data := "my data"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("POST", url, strings.NewReader(data))
  if err != nil {
    t.Errorf("Expected no error")
  }

  f := createItemHandler(space)
  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expectedItemId := "141734987"

  expected_body := "{\"item_id\":\"" + expectedItemId + "\",\"parent_id\":\"\"}\n"

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }

  filePath := filepath.Join(space.DataDirPath(), bucketId, expectedItemId)

  if _, err := os.Stat(filePath); err != nil {
    t.Errorf("File '%v' should exist but doesn't", filePath)
  }

  expectedContent1 := "{\"item_id\":\"" + expectedItemId + "\",\"parent_id\":\"\",\"content\":\"" + data + "\"}"

  content, _ := ioutil.ReadFile(filePath)
  content_string := string(content)
  if content_string != expectedContent1 {
    t.Errorf("Got content '%v', expected '%v'", content_string, expectedContent1)
  }


  data2 := "more data"

  recorder = httptest.NewRecorder()
  req, err = http.NewRequest("POST", url, strings.NewReader(data2))
  if err != nil {
    t.Errorf("Expected no error")
  }

  expectedItemId2 := "297281668"

  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expected_body = "{\"item_id\":\"" + expectedItemId2 + "\",\"parent_id\":\"" + expectedItemId + "\"}\n"

  body = recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }

  filePath = filepath.Join(space.DataDirPath(), bucketId, expectedItemId2)

  if _, err = os.Stat(filePath); err != nil {
    t.Errorf("File '%v' should exist but doesn't", filePath)
  }

  expectedContent2 := "{\"item_id\":\"" + expectedItemId2 + "\",\"parent_id\":\"" + expectedItemId + "\",\"content\":\"" + data2 + "\"}"

  content, _ = ioutil.ReadFile(filePath)
  content_string = string(content)
  if content_string != expectedContent2 {
    t.Errorf("Got content '%v', expected '%v'", content_string, expectedContent2)
  }


  recorder = httptest.NewRecorder()
  req, err = http.NewRequest("GET", url, nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  f = readItemsHandler(space)
  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expected_body = "[" + expectedContent2 + "," + expectedContent1 + "]\n"

  body = recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestCreateToken(t *testing.T) {
  rand.Seed(42)

  expectedToken := "9354231278675"
  expectedBody := "{\"token\":\"" + expectedToken + "\"}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("POST", "http://example.com/token", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  f := createTokenHandler(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }

  tokenPath := filepath.Join(space.TokenDirPath(), expectedToken)

  if _, err := os.Stat(tokenPath); err != nil {
    t.Errorf("File '%v' should exist but doesn't", tokenPath)
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

  expected_body := "[\"" + tokens[0] + "\",\"" + tokens[1] + "\"]\n"

  f := adminListTokens(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestAdminListTokensEmpty(t *testing.T) {
  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/tokens", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  expected_body := "[]\n"

  f := adminListTokens(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestUserRegister(t *testing.T) {
  rand.Seed(42)

  expectedUserId := "141734987"
  expectedUserPassword := "297281668"
  expected_body := "{\"user_id\":\"" + expectedUserId + "\",\"user_password\":\"" + expectedUserPassword + "\"}\n"

  space := createTestSpace()
  token, _ := space.CreateToken()

  tokenPath := filepath.Join(space.TokenDirPath(), token)
  if _, err := os.Stat(tokenPath); err != nil {
    t.Errorf("File '%v' should exist but doesn't", tokenPath)
  }


  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/register/invalid_token", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  f := userRegisterHandler(space)
  f(recorder, req, map[string]string{"token":"invalid_token"})

  expectedCode := 404
  code := recorder.Code
  if code != expectedCode {
    t.Errorf("Expected response code '%v', got '%v'", expectedCode, code)
  }


  recorder = httptest.NewRecorder()
  req, err = http.NewRequest("GET", "http://example.com/register/" + token, nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  f(recorder, req, map[string]string{"token":token})

  expectedCode = 200
  code = recorder.Code
  if code != expectedCode {
    t.Errorf("Expected response code '%v', got '%v'", expectedCode, code)
  }

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }

  if _, err := os.Stat(tokenPath); err == nil {
    t.Errorf("File '%v' should not exist but does", tokenPath)
  }

  userPasswordHash := space.users[expectedUserId].PasswordHash
  err = bcrypt.CompareHashAndPassword([]byte(userPasswordHash), []byte(expectedUserPassword))
  if err != nil {
    t.Errorf("Expected user '%v' with password '%v' and hash '%v', didn't match", expectedUserId, expectedUserPassword, userPasswordHash)
  }
}

func TestUserClients(t *testing.T) {
  expected_body := "{\"admins\":[],\"users\":[\"94099423\"]}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/clients", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  admins := make(map[string]User)

  users := make(map[string]User)
  users["94099423"] = User{"xxx"}

  f := adminClients(admins, users)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestMergeUserArrays(t *testing.T) {
  admins := make(map[string]User)
  admins["94088423"] = User{"yyy"}

  users := make(map[string]User)
  users["94099423"] = User{"xxx"}

  allUsers := mergeUsers(admins, users)

  if allUsers["94088423"].PasswordHash != "yyy" {
    t.Errorf("Didn't find admin user")
  }
  if allUsers["94099423"].PasswordHash != "xxx" {
    t.Errorf("Didn't find user user")
  }

  if admins["94099423"].PasswordHash == "xxx" {
    t.Errorf("Shouldn't alter original map")
  }
  if users["94088423"].PasswordHash == "yyy" {
    t.Errorf("Shouldn't alter original map")
  }
}
