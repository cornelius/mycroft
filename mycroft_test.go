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
)

func TestCreateAdmin(t *testing.T) {
  rand.Seed(42)
  expected_id := "801072305"
  expected_password := "141734987"

  id, password, _ := createAdmin()

  if id != expected_id {
    t.Errorf("createAdmin() = '%v, _', want '%v'", id, expected_id)
  }
  if password != expected_password {
    t.Errorf("createAdmin() = '_, %v', want '%v'", password, expected_password)
  }
}

func TestAdminsAsJson(t *testing.T) {
  var admins map[string]Admin
  admins = make(map[string]Admin)

  id, _, admin := createAdmin()
  admin.PasswordHash = "$2a$10$36ZaYv02CY1PQxFiiuTtu.K6soUBCK330yLXwBvcaeREGfj.Bx/kC"
  admins[id] = admin

  json_string, _ := adminsAsJson(admins)
  expected_json_string := "[\"297281668\"]"

  if json_string != expected_json_string {
    t.Errorf("adminsAsJson() = '%v', want '%v'", json_string, expected_json_string)
  }
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
  expected_body := "{\"admin_id\":\"94099423\",\"password\":\"822901345\"}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/register/1234", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  space := Space{"/tmp/mycroft-test", make(map[string]Admin), false}

  f := adminRegisterHandler(1234, space)
  f(recorder, req, map[string]string{"pid":"1234"})

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestAdminClients(t *testing.T) {
  expected_body := "[\"94099423\"]\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("GET", "http://example.com/admin/clients", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  admins := make(map[string]Admin)
  admins["94099423"] = Admin{"xxx"}

  f := adminClients(admins)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}

func TestCreateBucket(t *testing.T) {
  expected_body := "{\"bucket_id\":\"745640357\"}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("POST", "http://example.com/data", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  testDir := "/tmp/mycroft-test1"
  os.RemoveAll(testDir)
  space := Space{testDir, make(map[string]Admin), false}

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

  admins := make(map[string]Admin)
  admins["94099423"] = Admin{"xxx"}

  testDir := "/tmp/mycroft-test2"
  os.RemoveAll(testDir)
  space := Space{testDir, make(map[string]Admin), false}

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

func TestWriteAndReadItems(t *testing.T) {
  testDir := "/tmp/mycroft-test3"
  os.RemoveAll(testDir)

  space := Space{testDir, make(map[string]Admin), false}

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

  expectedItemId := "579751929"

  expected_body := "{\"item_id\":\"" + expectedItemId + "\",\"parent_id\":\"\"}\n"

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }

  filePath := filepath.Join("/tmp/mycroft-test3/data", bucketId, expectedItemId)

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

  expectedItemId2 := "468025967"

  f(recorder, req, map[string]string{"bucket_id":bucketId})

  expected_body = "{\"item_id\":\"" + expectedItemId2 + "\",\"parent_id\":\"" + expectedItemId + "\"}\n"

  body = recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }

  filePath = filepath.Join("/tmp/mycroft-test3/data", bucketId, expectedItemId2)

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
  expectedToken := "4666146214990"
  expectedBody := "{\"token\":\"" + expectedToken + "\"}\n"

  recorder := httptest.NewRecorder()
  req, err := http.NewRequest("POST", "http://example.com/token", nil)
  if err != nil {
    t.Errorf("Expected no error")
  }

  testDir := "/tmp/mycroft-test1"
  os.RemoveAll(testDir)
  space := Space{testDir, make(map[string]Admin), false}

  f := createTokenHandler(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expectedBody {
    t.Errorf("Expected body '%v', got '%v'", expectedBody, body)
  }

  tokenPath := filepath.Join("/tmp/mycroft-test1/tokens", expectedToken)

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

  testDir := "/tmp/mycroft-test2"
  os.RemoveAll(testDir)
  space := Space{testDir, make(map[string]Admin), false}

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

  testDir := "/tmp/mycroft-test2"
  os.RemoveAll(testDir)
  space := Space{testDir, make(map[string]Admin), false}

  expected_body := "[]\n"

  f := adminListTokens(space)
  f(recorder, req)

  body := recorder.Body.String()
  if body != expected_body {
    t.Errorf("Expected body '%v', got '%v'", expected_body, body)
  }
}
