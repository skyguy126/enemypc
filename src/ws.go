package main

import (
	"bytes"
	"fmt"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	jwt "github.com/dgrijalva/jwt-go"
	mux "github.com/gorilla/mux"
	sessions "github.com/gorilla/sessions"
	websocket "github.com/gorilla/websocket"
	alice "github.com/justinas/alice"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"strconv"
	"time"
)

//TODO
//verify trade url if(url.match(/token=([\w-]+)/)) with regex
//prevent directory listing
//implement crsf http://www.gorillatoolkit.org/pkg/csrf
//https://gyazo.com/440cd2eaae0ad7a48e84604d356d73c4
//implement routers http://www.gorillatoolkit.org/pkg/mux
//websocket read limit
//session cookie
//null byte trimming
//check content length and deny unreasonably large requests
//middleware
//rate limiting
//get username picture... send thru websocket
//try and switch token to ECDSA crypto

//Make sure to use https port in HOST_ADDR
const HOST_ADDR string = "24.4.237.252:443"
const HOST_HTTP_PORT string = ":80"
const HOST_HTTPS_PORT string = ":443"

//token valid is seconds, session valid is days
const TOKE_VALID_TIME = 30
const SESS_VALID_TIME = 3

//DO NOT EDIT THESE
var COOKIE_SECRET string
var STEAM_API_KEY string
var STEAM_OID_LOGIN_URL string
var INDEX_HTML string
var HOME_HTML string

var sessionStore *sessions.CookieStore
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func MainHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, INDEX_HTML)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, HOME_HTML)
}

func SockHandler(w http.ResponseWriter, r *http.Request) {
	var checkHCon bool = false
	var checkHUp bool = false

	if len(r.Header["Connection"]) == 1 && len(r.Header["Upgrade"]) == 1 {
		checkHCon = strings.Compare(TrimNullBytes(r.Header["Connection"][0]), "Upgrade") == 0
		checkHUp = strings.Compare(TrimNullBytes(r.Header["Upgrade"][0]), "websocket") == 0
	}

	if !checkHCon || !checkHUp {
		log.Error("Invalid request to /sock from ", r.RemoteAddr, ", redirecting to /")
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}

	conn, connErr := upgrader.Upgrade(w, r, nil)
	if connErr != nil {
		log.Error("Websocket upgrade error for ", r.RemoteAddr, ": ", connErr.Error())
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}
	log.Info("Websocket connected from ", r.RemoteAddr)

	//TODO socket readlimits
	_, data, readErr := conn.ReadMessage()
	if readErr != nil || strings.Contains(string(data), "=") == false {
		log.Error("Socket read (auth token) error from, ", conn.RemoteAddr, ": ", readErr.Error())
		conn.Close()
		return
	}
	cookieStr := strings.Split(string(bytes.Trim(data, "\x00")), "=")[1]

	//TODO make this easier to read
	token, tokenErr := jwt.Parse(cookieStr, func(token *jwt.Token) (interface{}, error) {
		//validate algorithm used to sign
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Invalid signing method: ", token.Header["alg"])
		}
		return []byte(COOKIE_SECRET), nil
	})

	if tokenErr != nil {
		log.Error("Error validating token from, ", conn.RemoteAddr, ": ", tokenErr.Error())
		conn.Close()
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		log.Warn("Invalid token from ", conn.RemoteAddr)
		conn.Close()
		return
	}

	expTime, _ := strconv.ParseInt(claims["exp"].(string), 10, 64)
	remAddr, _ := claims["ip"].(string)
	steam64id, _ := claims["sid"].(string)

	expBool := expTime <= time.Now().Unix()
	remAddrBool := strings.Compare(remAddr, strings.Split(conn.RemoteAddr().String(), ":")[0]) != 0
	if expBool || remAddrBool {
		switch {
			case expBool:
				log.Warn("Expired token from ", conn.RemoteAddr)
			case remAddrBool:
				log.Warn("Token ip addr mismatch: ", conn.RemoteAddr)
			default:
				conn.Close()
				return
		}
	}

	params := url.Values{}
	params.Add("key", STEAM_API_KEY)
	params.Add("steamids", steam64id)
	resp, _ := http.Get("http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?" + params.Encode())
	apiData, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(apiData))
	/*
		token, _ := jwt.Parse(cookieStr, func(token *jwt.Token) ([]byte, error) {
				return []byte(COOKIE_SECRET), nil
		})
		fmt.Printf("%T\n", token)
		fmt.Println("state:", token.Valid)

		for {
			messageType, p, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err = conn.WriteMessage(messageType, p); err != nil {
				return
			}
		}
	*/
}

func OidHandler(w http.ResponseWriter, r *http.Request) {
	mode := TrimNullBytes(mux.Vars(r)["mode"])
	if mode == "login" {
		OidLoginHandler(w, r)
	} else if mode == "auth" {
		OidAuthHandler(w, r)
	} else {
		log.Warn("Invalid oid mode from ", r.RemoteAddr, ", redirecting to /")
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}
}

func OidLoginHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, STEAM_OID_LOGIN_URL, http.StatusMovedPermanently)
}

func OidAuthHandler(w http.ResponseWriter, r *http.Request) {
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
		steam64id = TrimNullBytes(params.Get("openid.identity"))[36:53]
		match, regErr := regexp.MatchString("[0-9]", steam64id)
		if match == false {
			log.Warn("Invalid (non-numeric) steam64 ID returned for ", r.RemoteAddr, ", redirecting to /")
			http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
			return
		} else if regErr != nil {
			log.Error("Regex error on steam64 ID for ", r.RemoteAddr, ", redirecting to /")
			http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
			return
		}
	} else {
		log.Warn("Invalid (invalid length) steam64 ID returned for ", r.RemoteAddr, ", redirecting to /")
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}

	resp, err := http.PostForm("https://steamcommunity.com/openid/login", params)
	if err != nil {
		log.Error("Auth request for ", r.RemoteAddr, " failed, redirecting to /")
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Read auth response for ", r.RemoteAddr, " failed, redirecting to /")
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}

	is_valid := strings.Split(strings.Split(strings.Trim(string(data), "\n"), "\n")[1], ":")[1]
	if strings.Compare(is_valid, "true") == 0 {
		log.Info("Addr ", r.RemoteAddr, " has been authenticated")

		session, sessionErr := sessionStore.Get(r, "session")
		if sessionErr != nil {
			log.Error("Error getting session for ", r.RemoteAddr, ": ", sessionErr.Error())
		}

		session.Options = &sessions.Options{
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400 * SESS_VALID_TIME,
			Secure:   true,
		}

		session.Values["sid"] = steam64id
		session.Values["exp"] = string(time.Now().Add(time.Hour * 24 * SESS_VALID_TIME).Unix())
		session.Values["ip"] = strings.Split(r.RemoteAddr, ":")[1]

		//TODO add expire field and check
		saveErr := session.Save(r, w)
		if saveErr != nil {
			log.Error("Error saving session for ", r.RemoteAddr, ": ", saveErr.Error(), " redirecting to /")
			http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
			return
		}

		log.Info("Generated session cookie for ", r.RemoteAddr)

		GenSockAuthCookie(w, r, steam64id)

		http.Redirect(w, r, "https://"+HOST_ADDR+"/home", http.StatusMovedPermanently)
		return
	} else {
		log.Warn("Addr ", r.RemoteAddr, " auth fail, redirecting to /")
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}
}

func GenSockAuthCookie(w http.ResponseWriter, r *http.Request, steam64id string) {
	tokenExp := time.Now().Add(time.Second * TOKE_VALID_TIME)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sid" : steam64id,
		"exp" : strconv.FormatInt(tokenExp.Unix(), 10),
		"ip" : strings.Split(string(r.RemoteAddr), ":")[0],
	})

	tokenString, tokenErr := token.SignedString([]byte(COOKIE_SECRET))

	if tokenErr != nil {
		log.Error("Error generating token for ", r.RemoteAddr, ": ", tokenErr.Error())
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}

	cookie := &http.Cookie{
		Name:     "sock_auth",
		Value:    tokenString,
		Expires:  tokenExp,
		HttpOnly: false,
		Secure:   true,
		Path:     "/home",
	}
	http.SetCookie(w, cookie)

	log.Info("Set jwt sock_auth cookie for ", r.RemoteAddr, ", redirecting to /home")
}

func TrimNullBytes(input string) string {
	return string(bytes.Trim([]byte(input), "\x00"))
}

func RedirectToHttps(w http.ResponseWriter, r *http.Request) {
	log.Info("Redirecting ", r.RemoteAddr, " to HTTPS /")
	http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
}

func NoDirListing(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	//TODO custom 404 page
	fmt.Fprint(w, "replace with custom 404 page")
}

func RecoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func(w http.ResponseWriter) {
			err := recover()
			if err != nil {
				log.Error("Unexpected panic from ", r.RemoteAddr, ": ", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}(w)
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

//TODO do not log time for connections to /sock
func LogHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		next.ServeHTTP(w, r)
		log.Info(r.RemoteAddr, " ", r.Method, " ", r.URL.Path, " ", time.Now().Sub(startTime))
	}
	return http.HandlerFunc(fn)
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

	sessionSecret, sessionSecretError := ioutil.ReadFile("secure/session_secret.txt")
	if sessionSecretError != nil {
		log.Fatal("Error loading session secret: ", sessionSecretError.Error())
		return
	}
	sessionStore = sessions.NewCookieStore(sessionSecret)
	log.Info("Loaded session secret")

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
	params.Add("openid.return_to", "https://"+HOST_ADDR+"/oid/auth")
	params.Add("openid.realm", "https://"+HOST_ADDR)
	params.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	params.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
	STEAM_OID_LOGIN_URL = "https://steamcommunity.com/openid/login?" + params.Encode()

	r := mux.NewRouter()
	r.StrictSlash(true)
	r.NotFoundHandler = http.HandlerFunc(NotFoundHandler)
	chain := alice.New(RecoverHandler, LogHandler)

	r.Handle("/", chain.ThenFunc(MainHandler)).Methods("GET")
	r.Handle("/home", chain.ThenFunc(HomeHandler)).Methods("GET")
	r.Handle("/sock", chain.ThenFunc(SockHandler)).Methods("GET")
	r.Handle("/oid/{mode:[a-z]+}", chain.ThenFunc(OidHandler)).Methods("GET")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", NoDirListing(http.FileServer(http.Dir("./static/")))))

	http.Handle("/", r)

	log.Info("Starting servers...")

	//TODO catch error
	go http.ListenAndServeTLS(HOST_HTTPS_PORT, "secure/server.crt", "secure/server.key", nil)
	http.ListenAndServe(HOST_HTTP_PORT, http.HandlerFunc(RedirectToHttps))
}
