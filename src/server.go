package main

import (
    "fmt"
    "net/http"
    "io/ioutil"
    "strings"
)

var STEAM_API_KEY string

var INDEX_HTML string

func redirectToHttps(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, INDEX_HTML)
    }
}

func main() {
    apiKey, apiKeyFileError := ioutil.ReadFile("secure/apikey.txt")
    if apiKeyFileError != nil {
        fmt.Println("KeyFile error:", apiKeyFileError.Error())
        return
    }
    STEAM_API_KEY = strings.Trim(string(apiKey), "\n ")

    fmt.Println("Api key:", STEAM_API_KEY)

    indexHtmlFile, indexHtmlFileError := ioutil.ReadFile("index.html")
    if indexHtmlFileError != nil {
        fmt.Println("index html file error:", indexHtmlFileError.Error())
        return
    }
    INDEX_HTML = strings.Trim(string(indexHtmlFile), "\n ")

    fmt.Println("Index html:", INDEX_HTML)

    fmt.Println("Starting servers...")

    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
    http.HandleFunc("/", mainHandler)
    go http.ListenAndServeTLS(":443", "secure/server.crt", "secure/server.key", nil)
    http.ListenAndServe(":80", http.HandlerFunc(redirectToHttps))
}
