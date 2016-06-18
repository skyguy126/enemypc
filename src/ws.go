package main

import (
	"bytes"
	"fmt"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	jwt "github.com/dgrijalva/jwt-go"
	mux "github.com/gorilla/mux"
	jason "github.com/antonholmquist/jason"
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
//https://gyazo.com/440cd2eaae0ad7a48e84604d356d73c4
//implement routers http://www.gorillatoolkit.org/pkg/mux
//websocket read limit
//session cookie
//null byte trimming
//check content length and deny unreasonably large requests
//middleware
//rate limiting, throttler
//make sure jwt token is only one time use
//socket timeouts
//status codes for websocket

//Make sure to use https port in HOST_ADDR
const HOST_ADDR string = "24.4.237.252:443"
const HOST_HTTP_PORT string = ":80"
const HOST_HTTPS_PORT string = ":443"

//token valid is seconds, session valid is days
const TOKEN_VALID_TIME = 20
const SESS_VALID_TIME = 3

//DO NOT EDIT THESE
var COOKIE_SECRET string
var STEAM_API_KEY string
var INDEX_HTML string
var HOME_HTML string

var steamApiUrl string = "http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?"
var sessionStore *sessions.CookieStore
var upgrader = websocket.Upgrader{
	HandshakeTimeout: time.Second * 15,
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func MainHandler(w http.ResponseWriter, r *http.Request) {
	//TODO add redirection to /home if session exists
	fmt.Fprint(w, INDEX_HTML)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	//TODO delete session if from new ip
	session, sessionErr := sessionStore.Get(r, "session")
	if sessionErr != nil {
		log.Error("Error getting session for ", r.RemoteAddr, ": ", sessionErr.Error())
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
	}

	if !session.IsNew {
		expTime, _ := strconv.ParseInt(session.Values["exp"].(string), 10, 64)
		remAddr, _ := session.Values["ip"].(string)
		isExpired := expTime <= time.Now().Unix()
		isDifferentIp := strings.Compare(remAddr, strings.Split(r.RemoteAddr, ":")[0]) != 0
		//TODO make code better
		if isExpired || isDifferentIp {
			if isExpired {
				log.Warn("Session ip addr mismatch: ", r.RemoteAddr, ", ", remAddr)
			} else if isDifferentIp {
				log.Warn("Expired session from ", r.RemoteAddr)
			}
			http.Redirect(w, r, "https://"+HOST_ADDR+"/oid/login", http.StatusMovedPermanently)
			return
		}

		log.Info("Logged in with session for ", r.RemoteAddr)

		if GenSockAuthCookie(w, r, session.Values["sid"].(string)) != nil {
			http.Redirect(w, r, "https://"+HOST_ADDR+"/", http.StatusMovedPermanently)
			return
		}
	}
	fmt.Fprint(w, HOME_HTML)
}

func MarshalAndSend(data map[string]string, conn *websocket.Conn, dataType int) error {
	json, jsonErr := json.Marshal(data)
	if jsonErr != nil {
		log.Error("Json marshal error for ", conn.RemoteAddr().String(), ": ", jsonErr.Error())
		return jsonErr
	}
	sendErr := conn.WriteMessage(dataType, json)
	if sendErr != nil {
		log.Error("Error sending message to ", conn.RemoteAddr().String(), ": ", sendErr.Error())
		return sendErr
	}
	return nil
}

func SockHandler(w http.ResponseWriter, r *http.Request) {
	var checkHCon bool = false
	var checkHUp bool = false

	if len(r.Header["Connection"]) == 1 && len(r.Header["Upgrade"]) == 1 {
		checkHCon = strings.Compare(TrimNullBytes(r.Header["Connection"][0]), "Upgrade") == 0
		checkHUp = strings.Compare(TrimNullBytes(r.Header["Upgrade"][0]), "websocket") == 0
	}

	if !checkHCon || !checkHUp {
		log.Warn("Invalid request to /sock from ", r.RemoteAddr, ", redirecting to /")
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

	//TODO this will only read 1024 bytes at a time, use headers
	conn.SetReadLimit(2048)
	messageType, data, readErr := conn.ReadMessage()
	if readErr != nil || len(data) < 1 || strings.Contains(string(data), "=") == false {
		if readErr != nil {
			log.Error("Socket read (auth token) error from, ", conn.RemoteAddr().String(), ": ", readErr.Error())
		} else {
			log.Warn("Invalid token received from ", conn.RemoteAddr().String())
		}
		conn.Close()
		return
	}

	cookieStr := strings.Split(string(bytes.Trim(data, "\x00")), "=")[1]

	token, tokenErr := jwt.Parse(cookieStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Invalid signing method: ", token.Header["alg"])
		}
		return []byte(COOKIE_SECRET), nil
	})

	if tokenErr != nil {
		log.Error("Error validating token from, ", conn.RemoteAddr().String(), ": ", tokenErr.Error())
		MarshalAndSend(map[string]string{"is_valid":"false"}, conn, messageType)
		conn.Close()
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		log.Warn("Invalid token from ", conn.RemoteAddr().String())
		MarshalAndSend(map[string]string{"is_valid":"false"}, conn, messageType)
		conn.Close()
		return
	}

	expTime, _ := strconv.ParseInt(claims["exp"].(string), 10, 64)
	remAddr, _ := claims["ip"].(string)
	steam64id, _ := claims["sid"].(string)

	isExpired := expTime <= time.Now().Unix()
	isDifferentIp := strings.Compare(remAddr, strings.Split(conn.RemoteAddr().String(), ":")[0]) != 0
	if isExpired || isDifferentIp {
		if isExpired {
			log.Warn("Expired token from ", conn.RemoteAddr().String())
		} else if isDifferentIp {
			log.Warn("Token ip addr mismatch: ", conn.RemoteAddr().String(), ", ", remAddr)
		}

		MarshalAndSend(map[string]string{"is_valid":"false"}, conn, messageType)
		conn.Close()
		return
	}

	if MarshalAndSend(map[string]string{"is_valid":"true"}, conn, messageType) != nil {
		conn.Close()
		return
	}

	params := url.Values{}
	params.Add("key", STEAM_API_KEY)
	params.Add("steamids", steam64id)

	resp, respErr := http.Get(steamApiUrl + params.Encode())
	if readErr != nil {
		log.Error("Error fetching userinfo with steam api ", conn.RemoteAddr().String(), ": ", respErr.Error())
		conn.Close()
		return
	}

	apiData, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		log.Error("Error reading response from steamapi for ", conn.RemoteAddr().String(), ": ", readErr.Error())
	}

	log.Info("Token validated for ", conn.RemoteAddr().String())

	payload, _ := jason.NewObjectFromBytes(apiData)
	allUserData, _ := payload.GetObjectArray("response", "players")
	for _, key := range allUserData {
		userNickname, _ := key.GetString("personaname")
		userAvatar, _ := key.GetString("avatarfull")
		userInfo := map[string]string{"nickname" : userNickname, "avatar" : userAvatar}
		if MarshalAndSend(userInfo, conn, messageType) != nil {
			conn.Close()
			return
		}
	}

	/*
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
		OidLoginHandler(w, r, false)
	} else if mode == "login_s" {
		OidLoginHandler(w, r, true)
	} else if mode == "auth" {
		OidAuthHandler(w, r, false)
	} else if mode == "auth_s" {
		OidAuthHandler(w, r, true)
	} else {
		log.Warn("Invalid oid mode from ", r.RemoteAddr, ", redirecting to /")
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}
}

func OidLoginHandler(w http.ResponseWriter, r *http.Request, saveSession bool) {
	params := url.Values{}
	params.Add("openid.ns", "http://specs.openid.net/auth/2.0")
	params.Add("openid.mode", "checkid_setup")
	if saveSession {
		params.Add("openid.return_to", "https://"+HOST_ADDR+"/oid/auth_s")
	} else {
		params.Add("openid.return_to", "https://"+HOST_ADDR+"/oid/auth")
	}
	params.Add("openid.realm", "https://"+HOST_ADDR)
	params.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	params.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")

	loginUrl := "https://steamcommunity.com/openid/login?" + params.Encode()
	http.Redirect(w, r, loginUrl, http.StatusMovedPermanently)
}

func OidAuthHandler(w http.ResponseWriter, r *http.Request, saveSession bool) {
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

		if saveSession {
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
			session.Values["exp"] = strconv.FormatInt(time.Now().Add(time.Hour * 24 * SESS_VALID_TIME).Unix(), 10)
			session.Values["ip"] = strings.Split(r.RemoteAddr, ":")[0]

			saveErr := session.Save(r, w)
			if saveErr != nil {
				log.Error("Error saving session for ", r.RemoteAddr, ": ", saveErr.Error(), " redirecting to /")
				http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
				return
			}

			log.Info("Generated session cookie for ", r.RemoteAddr)
		} else {
			if GenSockAuthCookie(w, r, steam64id) != nil {
				http.Redirect(w, r, "https://"+HOST_ADDR+"/", http.StatusMovedPermanently)
				return
			}
		}

		log.Info("Redirecting ", r.RemoteAddr, " to /home")
		http.Redirect(w, r, "https://"+HOST_ADDR+"/home", http.StatusMovedPermanently)
		return
	} else {
		log.Warn("Addr ", r.RemoteAddr, " auth fail, redirecting to /")
		http.Redirect(w, r, "https://"+HOST_ADDR, http.StatusMovedPermanently)
		return
	}
}

func GenSockAuthCookie(w http.ResponseWriter, r *http.Request, steam64id string) error {
	tokenExp := time.Now().Add(time.Second * TOKEN_VALID_TIME)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sid" : steam64id,
		"exp" : strconv.FormatInt(tokenExp.Unix(), 10),
		"ip" : strings.Split(string(r.RemoteAddr), ":")[0],
	})

	tokenString, tokenErr := token.SignedString([]byte(COOKIE_SECRET))
	if tokenErr != nil {
		log.Error("Error generating token for ", r.RemoteAddr, ": ", tokenErr.Error())
		return tokenErr
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
	log.Info("Set jwt sock_auth cookie for ", r.RemoteAddr)

	return nil
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
		defer func() {
			if err := recover(); err != nil {
				log.Error("Unexpected panic from ", r.RemoteAddr, ": ", err)
			}
		}()
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

	r := mux.NewRouter()
	r.StrictSlash(true)
	r.NotFoundHandler = http.HandlerFunc(NotFoundHandler)
	chain := alice.New(RecoverHandler, LogHandler)

	r.Handle("/", chain.ThenFunc(MainHandler)).Methods("GET")
	r.Handle("/home", chain.ThenFunc(HomeHandler)).Methods("GET")
	r.Handle("/sock", chain.ThenFunc(SockHandler)).Methods("GET")
	r.Handle("/oid/{mode:[a-z_]+}", chain.ThenFunc(OidHandler)).Methods("GET")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", NoDirListing(http.FileServer(http.Dir("./static/")))))

	http.Handle("/", r)

	log.Info("Starting servers...")

	//TODO catch error
	go http.ListenAndServeTLS(HOST_HTTPS_PORT, "secure/server.crt", "secure/server.key", nil)
	http.ListenAndServe(HOST_HTTP_PORT, http.HandlerFunc(RedirectToHttps))
}
