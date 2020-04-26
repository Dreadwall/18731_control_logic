import time
from IPy import IP
import http.server


HOST_NAME = '' 
PORT_NUMBER = 9090


class MyHandler(http.server.BaseHTTPRequestHandler):
    DemandServer_Callback = ""
    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
    def do_GET(s):
        """Respond to a GET request."""
        s.send_response(200)
        s.end_headers()
    def do_POST(s):
            try:
                self.parsed_uri = urlparse(self.path)
                # check regex match for ip address as path
                ip_check = path.replace("/", "")
                IP(ip_check) # error is thrown if not legal IP
                self.DemandServer_Callback(ip_check)
            except:
                print("An exception occurred")
                # redirect 
                s.send_response(501)
                s.end_headers()
    @classmethod
    def set_demand_callback(cls, new_callback):
        cls.DemandServer_Callback = new_callback
