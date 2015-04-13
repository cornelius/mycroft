package main

import (
  "fmt"
  "io"
)

type Diary struct {
  out io.Writer
}

var diary Diary

func (diary Diary) RegisteredAdminClient(pin string) {
  fmt.Fprintf(diary.out, "Registered admin client with pin %v\n", pin)
}

func (diary Diary) RegisteredUserClient(token string) {
  fmt.Fprintf(diary.out, "Registered user client with token %v\n", token)
}

func (diary Diary) CreatedToken(token string) {
  fmt.Fprintf(diary.out, "Created token %v\n", token)
}

func (diary Diary) CreatedBucket(id string) {
  fmt.Fprintf(diary.out, "Created bucket %v\n", id)
}

func (diary Diary) DeletedBucket(id string) {
  fmt.Fprintf(diary.out, "Deleted bucket %v\n", id)
}
