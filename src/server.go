package main

import (
    "fmt"
    "net/http"
    "net/url"
    "io/ioutil"
    "strings"
    "os"
    "time"
    log "github.com/Sirupsen/logrus"
    jwt "github.com/dgrijalva/jwt-go"
)

//TODO
//verify trade url if(url.match(/token=([\w-]+)/)) with regex
//prevent directory listing
//implement crsf http://www.gorillatoolkit.org/pkg/csrf
//https://gyazo.com/440cd2eaae0ad7a48e84604d356d73c4
//implement routers (gorilla)
//make jwt more secure
//websocket implementation

var COOKIE_SECRET string
var STEAM_API_KEY string
var STEAM_OID_LOGIN_URL string
var INDEX_HTML string
var HOME_HTML string

func redirectToHttps(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
}

func noDirListing(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        log.Info("GET / ", r.RemoteAddr)
        fmt.Fprint(w, INDEX_HTML)
    }
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        log.Info("GET /home ", r.RemoteAddr)
        fmt.Fprint(w, HOME_HTML)
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

        log.Info("Authenticating login request from ", r.RemoteAddr, " with Steam...")

        var steam64id string
        if len(params.Get("openid.identity")) == 53 {
            steam64id = params.Get("openid.identity")[36:53]
        } else {
            log.Error("Invalid steam64 ID returned for ", r.RemoteAddr, ", redirecting to home!")
            http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
            return
        }

        resp, err := http.PostForm("https://steamcommunity.com/openid/login", params)
        if err != nil {
            log.Error("Auth request for ", r.RemoteAddr, " failed, redirecting to home!")
            http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
            return
        }
        defer resp.Body.Close()
        data, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            log.Error("Read auth response for ", r.RemoteAddr, " failed, redirecting to home!")
            http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
            return
        }

        is_valid := strings.Split(strings.Split(strings.Trim(string(data), "\n"), "\n")[1], ":")[1]
        if strings.Compare(is_valid, "true") == 0 {
            log.Info("Addr ", r.RemoteAddr, " has been authenticated")

            token := jwt.New(jwt.SigningMethodHS256)
            tokenExp := time.Now().Add(time.Hour)

            token.Claims["steam64id"] = steam64id
            token.Claims["expire"] = string(tokenExp.Unix())
            tokenString, tokenErr := token.SignedString([]byte(COOKIE_SECRET))

            if tokenErr != nil {
                log.Error("Error generating token for ", r.RemoteAddr, ": ", tokenErr.Error())
                http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
                return
            }

            cookie := &http.Cookie {
                Name : "session",
                Value : tokenString,
                Expires : tokenExp,
            }
            http.SetCookie(w, cookie)

            log.Info("Set session cookie for ", r.RemoteAddr, ", redirecting to /home")
            http.Redirect(w, r, "https://24.4.237.252:443/home", http.StatusMovedPermanently)

        } else {
            log.Warn("Addr ", r.RemoteAddr, " auth fail, redirecting to home!")
            http.Redirect(w, r, "https://24.4.237.252:443", http.StatusMovedPermanently)
            return
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
    log.Info("Loaded API key")

    cookieSecret, cookieSecretError := ioutil.ReadFile("secure/cookie_secret.txt")
    if cookieSecretError != nil {
        log.Fatal("Error loading cookie secret: ", cookieSecretError.Error())
        return
    }
    COOKIE_SECRET = strings.Trim(string(cookieSecret), "\n ")
    log.Info("Loaded jwt cookie secret")

    indexHtmlFile, indexHtmlFileError := ioutil.ReadFile("index.html")
    if indexHtmlFileError != nil {
        log.Fatal("Error loading index.html: ", indexHtmlFileError.Error())
        return
    }
    INDEX_HTML = strings.Trim(string(indexHtmlFile), "\n ")
    log.Info("Loaded index.html")

    homeHtmlFile, homeHtmlFileError := ioutil.ReadFile("home.html")
    if homeHtmlFileError != nil {
        log.Fatal("Error loading index.html: ", homeHtmlFileError.Error())
        return
    }
    HOME_HTML = strings.Trim(string(homeHtmlFile), "\n ")
    log.Info("Loaded home.html")

    params := url.Values{}
    params.Add("openid.ns", "http://specs.openid.net/auth/2.0")
    params.Add("openid.mode", "checkid_setup")
    params.Add("openid.return_to", "https://24.4.237.252:443/oid/auth")
    params.Add("openid.realm", "https://24.4.237.252")
    params.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
    params.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
    STEAM_OID_LOGIN_URL = "https://steamcommunity.com/openid/login?" + params.Encode()

    log.Info("Built steam openid login url")
    log.Info("Starting servers...")

    http.HandleFunc("/", mainHandler)
    http.HandleFunc("/home", homeHandler)
    http.HandleFunc("/oid/login", oidLoginHandler)
    http.HandleFunc("/oid/auth", oidAuthHandler)

    http.Handle("/static/", http.StripPrefix("/static/", noDirListing(http.FileServer(http.Dir("./static")))))
    go http.ListenAndServeTLS(":443", "secure/server.crt", "secure/server.key", nil)
    http.ListenAndServe(":80", http.HandlerFunc(redirectToHttps))
}
