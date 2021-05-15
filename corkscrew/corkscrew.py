#!/usr/bin/python3
#
# corkscrew.py [Command line API integrator]
# Author: Jonathan Cormier <jonathan@cormier.co>
#
# https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
#
# 1xx informational response – the request was received, continuing process
# 2xx successful – the request was successfully received, understood, and accepted
# 3xx redirection – further action needs to be taken in order to complete the request
# 4xx client error – the request contains bad syntax or cannot be fulfilled
# 5xx server error – the server failed to fulfil an apparently valid request
#
import sys
import os
import readline
import json

from urllib.parse import urlparse
from urllib.request import urlopen, Request

CORKSCREW_VERSION = "0.1"
CORKSCREW_PROMPT = "corkscrew> "
CORKSCREW_SCHEME = "https"

CORKSCREW_HEADERS = {
	"User-Agent": "cAPI/" + CORKSCREW_VERSION,
	#"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	#"Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
	#"Accept-Encoding": "none"k,
	#"Accept-Language": "en-US,en;q=0.8",
	"Connection": "keep-alive"
}

# General headers - added by proxies
CORKSCREW_GENERAL_HEADERS = [
	"Via"
]

# Request headers
CORKSCREW_REQUEST_HEADERS = [
	"Host",
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"Referer",
	"Connection",
	"Upgrade-Insecure-Requests",
	"If-Modified-Since",
	"If-None-Match",
	"Cache-Control"
]

# Response headers
CORKSCREW_RESPONSE_HEADERS = [
	"Access-Control-Allow-Origin",
	"Accept-Ranges",
	"Age",
	"Connection",
	"Content-Encoding",
	"Content-Type",
	"Date",
	"Etag",
	"Keep-Alive",
	"Last-Modified",
	"Server",
	"Set-Cookie",
	"Transfer-Encoding",
	"Vary"
]

# Entity headers
CORKSCREW_ENTITY_HEADERS = [
	"Content-Length"
]

# Text colors
class colors:
	GREEN = '\033[32m'
	LIGHTGREEN = '\033[92m'
	RED = '\033[91m'
	PURPLE = '\033[95m'
	LIGHTPURPLE = '\033[94m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	CYAN = '\033[96m'
	UNDERLINE = '\033[4m'
	YELLOW = '\033[93m'
	BLACK = '\033[98m'
	
	# Background colors:
	GREYBG = '\033[100m'
	REDBG = '\033[101m'
	GREENBG = '\033[102m'
	YELLOWBG = '\033[103m'
	BLUEBG = '\033[104m'
	PINKBG = '\033[105m'
	CYANBG = '\033[106m'

def color_print(color, text):
	color_str = f"{color}{text}{colors.ENDC}"
	print(color_str)

def http_status(status):
	status_int = int(status)

	if status_int >= 200 and status_int <= 299:
		return "+"
	else:
		return "-"

def header_c(name):
	return None	

def response_color(code):
	return None
	
class Corkscrew:
	def __init__(self, url):
		self.url = url
		self.url_parts = urlparse(url, scheme=CORKSCREW_SCHEME)

	def get(self):
		# Build request	
		request = Request(self.url, None, CORKSCREW_HEADERS)
	
		color_print(colors.GREEN, "Sending GET to {}...".format(self.url))
		
		# Output request headers	
		for header,value in request.headers.items():
			print("{}: {}".format(header, value))
	
		color_print(colors.GREEN, "Response:")

		# Connection
		with urlopen(request) as conn:
			json_response = json.loads(conn.read().decode('utf-8'))
	
			# Output response headers
			for header,value in conn.headers.items():
				if header.startswith("X-"):
					header_color = colors.RED
				else:
					# Hightlight non-standard headers
					if header in CORKSCREW_GENERAL_HEADERS:
						header_color = colors.YELLOW
					elif header in CORKSCREW_ENTITY_HEADERS:
						header_color = colors.LIGHTGREEN
					elif header in CORKSCREW_RESPONSE_HEADERS:
						header_color = colors.ENDC
					else:
						header_color = colors.RED
	
				header_str = "{}: {}".format(header, value)
				color_print(header_color, header_str)

			print(json.dumps(json_response, indent=3, sort_keys=True))
			
			# Output status
			color_print(colors.CYAN, "{} {}".format(http_status(conn.status), conn.status))
	def post(self):
		print("Sending POST to", self.url)
	def patch(self):
		None
	def update(self):
		None
	def list_current_headers(self):
		print(CORKSCREW_HEADERS)
	def run_cmd(self, cmd, args=None):
		switcher = {
			"GET": self.get,
			"POST": self.post,
			"HEADERS": self.list_current_headers
		}
		
		return switcher.get(cmd.upper(), None)
	def prompt(self):
		line = ''

		# Loop		
		while True:
			line = input(CORKSCREW_PROMPT)
			line_split = line.split()
	
			if (len(line_split) == 0 or not line_split[0]):	
				continue
			else:
				if (line_split[0] == 'exit'):
					break

			cmd = line_split[0].upper()
			args = line_split[1:]	
				
			# Run function
			func = self.run_cmd(cmd, args)
			
			if func is not None:
				func()
	
if __name__ == "__main__":
	if (len(sys.argv) == 2):
		user_url = sys.argv[1]
	else:
		user_url = "http://localhost"

	print("Welcome to Corkscrew v{} by Jonathan Cormier".format(CORKSCREW_VERSION))

	cs = Corkscrew(user_url)
	cs.prompt()
