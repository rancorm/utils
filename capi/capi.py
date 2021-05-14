#!/usr/bin/python3
#
# capi.py [Command line API tool]
#
#
import sys
import os
import readline
import json

from urllib.parse import urlparse
from urllib.request import urlopen, Request

CAPI_PROMPT = "capi> "
CAPI_SCHEME = "https"

CAPI_HEADERS = {
	'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
	'Accept-Encoding': 'none',
	'Accept-Language': 'en-US,en;q=0.8',
	'Connection': 'keep-alive'
}

def color_print(color_, text):
	print("\033[2;{num}m{text}\033[0;0m".format(num=str(color_), text=text))

class CAPI:
	def __init__(self, url):
		self.url = url
		self.url_parts = urlparse(url, scheme=CAPI_SCHEME)

	def get(self):
		# Build request	
		request = Request(self.url, None, CAPI_HEADERS)
		
		print("Sending GET to " + self.url + "...")
		color_print(300, "Response:")

		with urlopen(request) as conn:
			json_response = json.loads(conn.read())
		
			print(conn.headers)	
			print(json.dumps(json_response, indent=3, sort_keys=True))
	def post(self):
		print("Sending POST to", self.url)	
	def run_cmd(self, cmd, args=None):
		switcher = {
			"GET": self.get,
			"POST": self.post
		}
		
		return switcher.get(cmd.upper(), lambda:"Invalid command")
	def prompt(self):
		line = ''

		# Loop		
		while True:
			line = input(CAPI_PROMPT)
			line_split = line.split()
	
			if (len(line_split) == 0 or not line_split[0]):	
				continue
			else:
				if (line_split[0] == 'exit'):
					break
	
			func = self.run_cmd(line_split[0], line_split[1:])
			func()
	
if __name__ == "__main__":
	if (len(sys.argv) == 2):
		user_url = sys.argv[1]
	else:
		user_url = "localhost"

	print("Welcome to cAPI by Jonathan Cormier <jonathan@cormier.co>")

	capi = CAPI(user_url)
	capi.prompt()
