package main

import (
  "testing"
  "math/rand"
  "net/http"
  "net/http/httptest"
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

func TestReadUsers(t *testing.T) {
  space := createTestSpace()

  // Should not fail
  space.ReadUsers()
}

func TestRoot(t *testing.T) {
  expectedBody := "hello\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  rootHandler(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}

func TestCreateBucket(t *testing.T) {
  rand.Seed(42)

  expectedBody := "{\"bucket_id\":\"hzwuvpx8k7\"}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("POST", "http://example.com/data", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := createTestSpace()

  f := createBucketHandler(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}

func TestWriteAndReadItems(t *testing.T) {
  rand.Seed(42)

  space := createTestSpace()

  bucketId, _ := space.CreateBucket()

  url := "http://example.com/data/" + bucketId


  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", url, nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  f := readItemsHandler(space)
  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expectedBody := "[]\n"

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }


  data := "my data"

  recorder = httptest.NewRecorder()
  req, err = http.NewRequest("POST", url, strings.NewReader(data))
  if err != nil {
    t.Errorf("Expected no error")
  }

  f = createItemHandler(space)
  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expectedItemId := "1b34w985zk"

  expectedBody = "{\"item_id\":\"" + expectedItemId + "\",\"parent_id\":\"\"}\n"

  body = recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }

  filePath := filepath.Join(space.DataDirPath(), bucketId, expectedItemId)

  if _, err := os.Stat(filePath); err != nil {
    t.Errorf("File '%v' should exist but doesn't", filePath)
  }

  expectedContent1 := "{\"item_id\":\"" + expectedItemId + "\",\"parent_id\":\"\",\"content\":\"" + data + "\"}"

  content, _ := ioutil.ReadFile(filePath)
  contentString := string(content)
  if contentString != expectedContent1 {
    t.Errorf("Got content '%v', expected '%v'", contentString, expectedContent1)
  }


  data2 := "more data"

  recorder = httptest.NewRecorder()
  req, err = http.NewRequest("POST", url, strings.NewReader(data2))
  if err != nil {
    t.Errorf("Expected no error")
  }

  expectedItemId2 := "y6srghejvb"

  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expectedBody = "{\"item_id\":\"" + expectedItemId2 + "\",\"parent_id\":\"" + expectedItemId + "\"}\n"

  body = recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }

  filePath = filepath.Join(space.DataDirPath(), bucketId, expectedItemId2)

  if _, err = os.Stat(filePath); err != nil {
    t.Errorf("File '%v' should exist but doesn't", filePath)
  }

  expectedContent2 := "{\"item_id\":\"" + expectedItemId2 + "\",\"parent_id\":\"" + expectedItemId + "\",\"content\":\"" + data2 + "\"}"

  content, _ = ioutil.ReadFile(filePath)
  contentString = string(content)
  if contentString != expectedContent2 {
    t.Errorf("Got content '%v', expected '%v'", contentString, expectedContent2)
  }


  recorder = httptest.NewRecorder()
  req, err = http.NewRequest("GET", url, nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  f = readItemsHandler(space)
  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expectedBody = "[" + expectedContent2 + "," + expectedContent1 + "]\n"

  body = recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}

func TestCreateToken(t *testing.T) {
  rand.Seed(42)

  expectedToken := "hzwuvpx8k71b34w9"
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

func TestUserRegister(t *testing.T) {
  rand.Seed(42)

  expectedUserId := "85zky6srgh"
  expectedUserPassword := "ejvbievihm"
  expectedBody := "{\"user_id\":\"" + expectedUserId + "\",\"user_password\":\"" + expectedUserPassword + "\"}\n"

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
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
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
  expectedBody := "{\"admins\":[],\"users\":[\"94099423\"]}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/clients", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  admins := make(map[string]User)

  users := make(map[string]User)
  users["94099423"] = User{"xxx"}

  f := adminListClientsHandler(admins, users)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}

func TestPing(t *testing.T) {
  expectedBody := "{\"ping\":\"pong\"}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/ping", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  f := pingHandler()
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }
}
