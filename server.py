from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from Okta_Phishing_Setup import ThreadedHTTPServer
from SocketServer import ThreadingMixIn
from threading import Lock, Thread
from urlparse import urlparse
import SocketServer
import simplejson
import threading
import optparse
import datetime
import requests
import urllib2
import Cookie
import random
import string
import signal
import bleach
import json
import time
import ssl
import sys
import os
import re
from threading import Thread, Lock


death = False
curr_count = 0
max_count = 5
mutex = Lock()

class Server(BaseHTTPRequestHandler):
  def do_HEAD(self):
    return
    
  def do_GET(self):
    self.respond()
    
  def do_POST(self):
    return
    
  def handle_http(self, status, content_type):
    self.send_response(status)
    self.send_header('Content-type', content_type)
    self.end_headers()

    mutex.acquire()
    curr_count += 1
    mutex.release()

    return bytes("Hello World", "UTF-8")
    
  def respond(self):
    if(death):
      content = self.handle_http(501, 'text/html')
    else:
      content = self.handle_http(200, 'text/html')
    self.wfile.write(content)

def sessions_management():
    global curr_count

    while True:
        time.sleep(5)
        if(curr_count >= max_count):
            death = True
        curr_count = 0


def start_server(handler_class=Server, port=4298):
  server_address = ('', port)
  httpd = ThreadedHTTPServer(server_address, handler_class)


  ses = Thread(target = sessions_management, args = [])
  ses.start()

  httpd.serve_forever()


if __name__ == '__main__':
  start_server(port=int(sys.argv[1]))
  
