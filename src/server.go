package main

import (
    "fmt"
    "net/http"
    "net/url"
    "io/ioutil"
    "strings"
)

var STEAM_API_KEY string
var INDEX_HTML string
var STEAM_OID_LOGIN_URL string

func redirectToHttps(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        fmt.Fprint(w, INDEX_HTML)
    }
}

func oidLoginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        http.Redirect(w, r, STEAM_OID_LOGIN_URL, http.StatusMovedPermanently)
    }
}

func oidAuthHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        //TODO
    }
}

func main() {
    apiKey, apiKeyFileError := ioutil.ReadFile("secure/apikey.txt")
    if apiKeyFileError != nil {
        fmt.Println("KeyFile error:", apiKeyFileError.Error())
        return
    }
    STEAM_API_KEY = strings.Trim(string(apiKey), "\n ")

    indexHtmlFile, indexHtmlFileError := ioutil.ReadFile("index.html")
    if indexHtmlFileError != nil {
        fmt.Println("index html file error:", indexHtmlFileError.Error())
        return
    }
    INDEX_HTML = strings.Trim(string(indexHtmlFile), "\n ")


    params := url.Values{}
    params.Add("openid.ns", "http://specs.openid.net/auth/2.0")
    params.Add("openid.mode", "checkid_setup")
    params.Add("openid.return_to", "https://24.4.237.252:443/oid/auth")
    params.Add("openid.realm", "https://24.4.237.252")
    params.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
    params.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
    STEAM_OID_LOGIN_URL = "https://steamcommunity.com/openid/login?" + params.Encode()

    fmt.Println("Starting servers...")

    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

    http.HandleFunc("/", mainHandler)
    http.HandleFunc("/oid/login", oidLoginHandler)
    http.HandleFunc("/oid/auth", oidAuthHandler)

    go http.ListenAndServeTLS(":443", "secure/server.crt", "secure/server.key", nil)
    http.ListenAndServe(":80", http.HandlerFunc(redirectToHttps))
}
