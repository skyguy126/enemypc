package main

import (
    "fmt"
    "net/http"
    "net/url"
    "io/ioutil"
    "strings"
    "os"
    log "github.com/Sirupsen/logrus"
)

var STEAM_API_KEY string
var STEAM_OID_LOGIN_URL string
var INDEX_HTML string

func redirectToHttps(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        log.Info("GET / ", r.RemoteAddr)
        fmt.Fprint(w, INDEX_HTML)
    }
}

func oidLoginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        log.Info("Redirecting ", r.RemoteAddr, " to steam login...")
        http.Redirect(w, r, STEAM_OID_LOGIN_URL, http.StatusMovedPermanently)
    }
}

func oidAuthHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        r.ParseForm()
        params := url.Values{}
        params.Add("openid.assoc_handle", r.Form.Get("openid.assoc_handle"))
        params.Add("openid.signed", r.Form.Get("openid.signed"))
        params.Add("openid.sig", r.Form.Get("openid.sig"))
        params.Add("openid.ns", "http://specs.openid.net/auth/2.0")
        params.Add("openid.mode", "check_authentication")
        params.Add("openid.op_endpoint", r.Form.Get("openid.op_endpoint"))
        params.Add("openid.claimed_id", r.Form.Get("openid.claimed_id"))
        params.Add("openid.identity", r.Form.Get("openid.identity"))
        params.Add("openid.return_to", r.Form.Get("openid.return_to"))
        params.Add("openid.response_nonce", r.Form.Get("openid.response_nonce"))
        resp, err := http.Post("https://steamcommunity.com/openid/login?" + params.Encode())
        if err != nil {
            log.Error("Auth request from ", r.RemoteAddr, " failed, redirecting to home!")
            http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
        }
    }
}

func main() {
    log.SetLevel(log.InfoLevel)
    log.SetOutput(os.Stdout)

    apiKey, apiKeyFileError := ioutil.ReadFile("secure/apikey.txt")
    if apiKeyFileError != nil {
        log.Fatal("Error loading API key:", apiKeyFileError.Error())
        return
    }
    STEAM_API_KEY = strings.Trim(string(apiKey), "\n ")
    log.Info("Loaded API key: ", STEAM_API_KEY)

    indexHtmlFile, indexHtmlFileError := ioutil.ReadFile("index.html")
    if indexHtmlFileError != nil {
        log.Fatal("Error loading index.html: ", indexHtmlFileError.Error())
        return
    }
    INDEX_HTML = strings.Trim(string(indexHtmlFile), "\n ")
    log.Info("Loaded index.html")


    params := url.Values{}
    params.Add("openid.ns", "http://specs.openid.net/auth/2.0")
    params.Add("openid.mode", "checkid_setup")
    params.Add("openid.return_to", "https://24.4.237.252:443/oid/auth")
    params.Add("openid.realm", "https://24.4.237.252")
    params.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
    params.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
    STEAM_OID_LOGIN_URL = "https://steamcommunity.com/openid/login?" + params.Encode()


    log.Info("Built steam openid login url: ", STEAM_OID_LOGIN_URL)
    log.Info("Starting servers...")

    http.HandleFunc("/", mainHandler)
    http.HandleFunc("/oid/login", oidLoginHandler)
    http.HandleFunc("/oid/auth", oidAuthHandler)

    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
    go http.ListenAndServeTLS(":443", "secure/server.crt", "secure/server.key", nil)
    http.ListenAndServe(":80", http.HandlerFunc(redirectToHttps))
}
