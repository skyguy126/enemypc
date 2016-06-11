import tornado.ioloop
import tornado.web
import tornado.template
import signal, random, os.path, steamapi, urllib

PORT = 9999

STEAM_API_KEY = ""

OID_PROVIDER = "http://steamcommunity.com/openid/login?"

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

class LoginHandler(tornado.web.RequestHandler):

    def get(self):
        params = {
            "openid.ns" : "http://specs.openid.net/auth/2.0",
            "openid.mode" : "checkid_setup",
            "openid.return_to" : "http://24.4.237.252:9999/oid",
            "openid.realm" : "http://24.4.237.252",
            "openid.identity" : "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.claimed_id" : "http://specs.openid.net/auth/2.0/identifier_select"
        }
        url = OID_PROVIDER + urllib.urlencode(params)
        self.redirect(url)

class OidHandler(tornado.web.RequestHandler):

    def get(self):
        self.render("index.html")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/search", SearchHandler),
        (r"/login", LoginHandler),
        (r"/oid", OidHandler),
    ], **settings)

if __name__ == "__main__":
    print "Starting server on port " + str(PORT)
    STEAM_API_KEY = raw_input("enter api key: ")
    steamapi.core.APIConnection(api_key=STEAM_API_KEY)

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = make_app()
    app.listen(PORT)
    tornado.ioloop.IOLoop.current().start()
