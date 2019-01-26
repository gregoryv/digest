package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gregoryv/digest"
	"github.com/gregoryv/logger"
)

func main() {
	var username, pwd string
	flag.StringVar(&username, "u", "", "Username")
	flag.StringVar(&pwd, "p", "", "Password")
	flag.Parse()

	info := logger.New()
	url := flag.Args()[0]
	auth := digest.NewAuth(username, pwd)

	// First request to get proper header
	resp, err := http.Head(url)
	exitOn(err)
	info.Logf(resp.Status)

	// Second request with authorization
	auth.Parse(resp.Header.Get("WWW-Authenticate"))
	req, err := http.NewRequest("GET", url, nil)
	exitOn(err)
	auth.Authorize(req)
	resp, err = http.DefaultClient.Do(req)
	exitOn(err)
	info.Log(resp.Status)
	io.Copy(os.Stdout, resp.Body)

	// Reuse for subsequent requests
	req, _ = http.NewRequest("GET", url, nil)
	auth.Authorize(req)
	resp, err = http.DefaultClient.Do(req)
	exitOn(err)
	info.Log(resp.Status)
}

func exitOn(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
