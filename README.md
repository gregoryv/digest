[![Build Status](https://travis-ci.org/gregoryv/digest.svg?branch=master)](https://travis-ci.org/gregoryv/digest)
[![codecov](https://codecov.io/gh/gregoryv/digest/branch/master/graph/badge.svg)](https://codecov.io/gh/gregoryv/digest)

[digest](https://godoc.org/github.com/gregoryv/digest) - package provides header generator for digest authentication.

## Quick start

    go get -u github.com/gregoryv/digest

## Example

The Auth object can be reused for subsequent requests thought it is
not thread safe.

    req, _ := http.NewRequest("GET", "/", nil)
    resp, _ := http.DefaultClient.Do(req)
    if resp.StatusCode == http.StatusUnauthorized {
        auth := NewAuth("john.doe", "secret")
        err := auth.Parse(resp.Header.Get("www-authenticate"))
        if err != nil {
            // cannot authenticate using this package
        }
        auth.Authorize(req)
    }
    resp, _ := http.DefaultClient.Do(req)

    // and for the next request just authorize it before sending
    auth.Authorize(req2)
