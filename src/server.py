import tornado.ioloop
import tornado.web
import tornado.template
import signal, os.path, steamapi, urllib, requests, json

PORT = 9999

STEAM_API_KEY = ""

settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
}

class MainHandler(tornado.web.RequestHandler):

    def get(self):
        print "get req from: " + str(self.request.remote_ip)
        self.set_header("Content-type","text/html")
        self.render("index.html")

class SearchHandler(tornado.web.RequestHandler):

    def post(self):
        steam_id = self.get_argument("id")
        user = steamapi.user.SteamUser(userurl=steam_id)
        friends = str(user.friends)
        self.write("{\'friends\':\'" + friends + "\'}")

class HomeHandler(tornado.web.RequestHandler):

    def get(self):
        pass

class OidLoginHandler(tornado.web.RequestHandler):

    #redirect to steam login page
    def get(self):
        params = {
            "openid.ns" : "http://specs.openid.net/auth/2.0",
            "openid.mode" : "checkid_setup",
            "openid.return_to" : "http://24.4.237.252:9999/oid/auth",
            "openid.realm" : "http://24.4.237.252",
            "openid.identity" : "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.claimed_id" : "http://specs.openid.net/auth/2.0/identifier_select"
        }
        self.redirect("https://steamcommunity.com/openid/login?" + urllib.urlencode(params))

class OidAuthHandler(tornado.web.RequestHandler):

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
        r = requests.post("https://steamcommunity.com/openid/login", params=params)
        if r.status_code == 200:
            for val in r.text.strip('\n').split('\n'):
                if val.split(':')[0] == "is_valid":
                    if val.split(':')[1] == "true":
                        self.redirect("/home")
                    else:
                        self.redirect("/oid/fail")
        else:
            print "auth request failed"

class OidFailHandler(tornado.web.RequestHandler):

    def get(self):
        pass

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/search", SearchHandler),
        (r"/oid/login", OidLoginHandler),
        (r"/oid/auth", OidAuthHandler),
        (r"/oid/fail", OidFailHandler),
        (r"/home", HomeHandler),
    ], **settings)

if __name__ == "__main__":
    print "Starting server on port " + str(PORT)
    STEAM_API_KEY = raw_input("enter api key: ")
    steamapi.core.APIConnection(api_key=STEAM_API_KEY)

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = make_app()
    app.listen(PORT)
    tornado.ioloop.IOLoop.current().start()
