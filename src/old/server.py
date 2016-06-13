import tornado.ioloop, tornado.template, tornado.web, tornado.httpserver, tornado.httputil
import signal, os.path, steamapi, urllib, requests, json

#TODO
#Make login async
#Regex login to avoid bug
#Gen secure cookie randomly associate with steam_id
#https://jwt.io/introduction/
#xss protection

STEAM_API_KEY = ""

COOKIE_SECRET = ""

settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
}

class MainHandler(tornado.web.RequestHandler):

    def prepare(self):
        if self.request.protocol == "http":
            self.redirect("https://24.4.237.252:443/", permanent=False)

    def get(self):
        self.set_header("Content-type","text/html")
        self.render("index.html")

class SearchHandler(tornado.web.RequestHandler):

    def prepare(self):
        if self.request.protocol == "http":
            self.redirect("https://24.4.237.252:443/", permanent=False)

    def post(self):
        steam_id = self.get_argument("id")
        user = steamapi.user.SteamUser(userurl=steam_id)
        friends = str(user.friends)
        self.write("{\'friends\':\'" + friends + "\'}")

class HomeHandler(tornado.web.RequestHandler):

    def prepare(self):
        if self.request.protocol == "http":
            self.redirect("https://24.4.237.252:443/", permanent=False)

    def get(self):
        self.write("Logged in!\n")

class OidLoginHandler(tornado.web.RequestHandler):

    def prepare(self):
        if self.request.protocol == "http":
            self.redirect("https://24.4.237.252:443/", permanent=False)

    #redirect to steam login page
    def get(self):
        params = {
            "openid.ns" : "http://specs.openid.net/auth/2.0",
            "openid.mode" : "checkid_setup",
            "openid.return_to" : "https://24.4.237.252:443/oid/auth",
            "openid.realm" : "https://24.4.237.252",
            "openid.identity" : "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.claimed_id" : "http://specs.openid.net/auth/2.0/identifier_select"
        }

        self.redirect("https://steamcommunity.com/openid/login?" + urllib.urlencode(params))

class OidAuthHandler(tornado.web.RequestHandler):

    def prepare(self):
        if self.request.protocol == "http":
            self.redirect("https://24.4.237.252:443/", permanent=False)

    #validate credentials
    def get(self):
        params = {
            "openid.assoc_handle" : self.get_argument("openid.assoc_handle"),
            "openid.signed" : self.get_argument("openid.signed"),
            "openid.sig" : self.get_argument("openid.sig"),
            "openid.ns" : "http://specs.openid.net/auth/2.0",
            "openid.mode" : "check_authentication",
            "openid.op_endpoint" : self.get_argument("openid.op_endpoint"),
            "openid.claimed_id" : self.get_argument("openid.claimed_id"),
            "openid.identity" : self.get_argument("openid.identity"),
            "openid.return_to" : self.get_argument("openid.return_to"),
            "openid.response_nonce" : self.get_argument("openid.response_nonce")
        }

        steam64id = params["openid.identity"][36:]
        r = requests.post("https://steamcommunity.com/openid/login", params=params)
        if r.status_code == 200 and len(steam64id) == 17:
            for val in r.text.strip('\n').split('\n'):
                if val.split(':')[0] == "is_valid":
                    if val.split(':')[1] == "true":
                        self.set_secure_cookie("session", steam64id, expires_days=None)
                        self.redirect("/home")
                    else:
                        self.redirect("/")
        else:
            self.redirect("/")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/search", SearchHandler),
        (r"/oid/login", OidLoginHandler),
        (r"/oid/auth", OidAuthHandler),
        (r"/home", HomeHandler),
    ], cookie_secret=COOKIE_SECRET, **settings)

if __name__ == "__main__":
    print "Loading secure files..."

    with open("secure/apikey.txt", 'r') as f:
        STEAM_API_KEY = f.read().strip('\n')
    with open("secure/cookie_secret.txt", 'r') as f:
        COOKIE_SECRET = f.read().strip('\n')

    steamapi.core.APIConnection(api_key=STEAM_API_KEY)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    print "Starting server..."

    http_server = tornado.httpserver.HTTPServer(make_app())
    http_server.listen(80)

    https_server = tornado.httpserver.HTTPServer(make_app(), ssl_options={
        "certfile" : "secure/server.crt",
        "keyfile" : "secure/server.key"
    })

    https_server.listen(443)
    tornado.ioloop.IOLoop.instance().start()
