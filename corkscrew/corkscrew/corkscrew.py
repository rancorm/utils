#!/usr/bin/python3
# coding: latin-1
#
# corkscrew.py [Command line API integrator]
# Author: Jonathan Cormier <jonathan@cormier.co>
#
# HTTP Status Codes
# =================
# 1xx  Informational Response – the request was received, continuing process
# 2xx  Successful – the request was successfully received, understood, and accepted
# 3xx  Redirection – further action needs to be taken in order to complete the request
# 4xx  Client Error – the request contains bad syntax or cannot be fulfilled
# 5xx  Server Error – the server failed to fulfil an apparently valid request
#
# https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
#
import sys
import os
import readline
import json

from signal import signal, SIGINT

from urllib.parse import urlparse
from urllib.request import urlopen, build_opener, Request, HTTPCookieProcessor
from urllib.error import HTTPError

# Cookie monster love cookies!
from http.cookiejar import CookieJar, DefaultCookiePolicy

CORKSCREW_VERSION = "0.1"
CORKSCREW_PROMPT = "{}[{}]> "
# Default protocol scheme
CORKSCREW_SCHEME = "https"
CORKSCREW_DEFAULT_METHOD = "GET"
CORKSCREW_AUTHOR = "Jonathan Cormier"

CORKSCREW_CODEC = "latin-1"

CORKSCREW_HEADERS = {
	"User-Agent": "Corkscrew/" + CORKSCREW_VERSION,
	"Accept": "*/*",
	#"Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
	#"Accept-Encoding": "none",
	#"Accept-Language": "en-US,en;q=0.8",
	"Connection": "keep-alive"
}

CORKSCREW_REQUEST_METHODS = [
	"CONNECT",
	"DELETE",
	"GET",
	"HEAD",
	"OPTIONS",
	"PATCH",
	"POST",
	"PUT",
	"TRACE"
]

# Deprecated headers
CORKSCREW_DEPRECATED_HEADERS = [
	"Accept-CH-Lifetime",
	"DPR",
	"Public-Key-Pins-Report-Only",
	"Public-Key-Pins"
]

# General headers - added by proxies
CORKSCREW_GENERAL_HEADERS = [
	"Via",
	"Connection",
	"Cache-Control",
	"Date",
	"Keep-Alive",
	"Pragma",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"Want-Digest",
	"Warning"
]

# Request headers
CORKSCREW_REQUEST_HEADERS = [
	"User-Agent",
	"Accept",
	"Accept-Charset",
	"Accept-Encoding",
	"Accept-Language",
	"Access-Control-Request-Headers",
	"Access-Control-Request-Method",
	"Authorization",
	"DNT",
	"Early-Data",
	"Connection",
	"Expect",
	"Forward",
	"From",
	"Host",
	"If-Match",
	"If-Modified-Since",
	"If-None-Match",
	"If-Range",
	"If-Unmodified-Since",
	"Upgrade-Insecure-Requests",
	"Cookie",
	"Origin",
	"Proxy-Authorization",
	"Range",
	"Referer",
	"Save-Data",
	"TE",
	"Upgrade-Insecure-Requests",
	"User-Agent",	
	# Experimental
	"Device-Memory"
]

# Response headers
CORKSCREW_RESPONSE_HEADERS = [
	"Accept-CH",
	"Accept-Path",
	"Accept-Post",
	"Accept-Ranges",
	"Access-Control-Allow-Credentials",
	"Access-Control-Allow-Headers",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Origin",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
	"Age",
	"Clear-Site-Data",
	"Content-Disposition",	
	"Content-Encoding",
	"Content-Range",
	# Standard header name proposed by the W3C document
	# X-Content-Security-Policy & X-WebKit-CSP are deprecated
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"Content-Security-Policy-Report",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
	"Digest",
	"Etag",
	"Expect-CT",
	"Expires",
	"Feature-Policy",
	# Firefox only for now
	"Large-Allocation",
	"Last-Modified",
	"Location",
	"NEL",
	# Was Features-Policy
	"Permissions-Policy",
	"Proxy-Authenticate",
	"Referrer-Policy",
	"Retry-After",	
	"Server-Timing",
	"Server",
	"Set-Cookie",
	"SourceMap",
	"Strict-Transport-Security",
	"Timing-Allow-Origin",
	"Tk",
	"Vary",
	"WWW-Authenticate"
]

CORKSCREW_REPR_HEADERS = [
	"Content-Language",
	"Content-Location"
]

# Entity headers
CORKSCREW_ENTITY_HEADERS = [
	"Content-Encoding",
	"Content-Length",
	"Allow",
	"Content-Type",
	"Link"
]

# Text colors
class colors:
	GREEN = "\033[32m"
	LIGHTGREEN = "\033[92m"
	RED = "\033[31m"
	LIGHTRED = "\033[91m"
	PURPLE = "\033[35m"
	PINK = "\033[95m"
	ENDC = "\033[0m"
	BOLD = "\033[1m"
	CYAN = "\033[36m"
	LIGHTCYAN = "\033[96m"
	UNDERLINE = "\033[4m"
	YELLOW = "\033[93m"
	LIGHTGRAY = "\033[98m"
	DARKGRAY = "\033[90m"
	ORANGE = "\033[33m"
	BLUE = "\033[34m"
	LIGHTBLUE = "\033[94m"
	
	# Background colors:
	GREYBG = "\033[100m"
	REDBG = "\033[101m"
	GREENBG = "\033[102m"
	YELLOWBG = "\033[103m"
	BLUEBG = "\033[104m"
	PINKBG = "\033[105m"
	CYANBG = "\033[106m"

def color_print(color, text, newline=True):
	color_str = "{}{}{}".format(color, text, colors.ENDC)

	# Newline?
	end_line = ""
	if newline:
		end_line = "\n"

	print(color_str, end=end_line)

def file_exists(path_to_file):
	return os.path.exists(path_to_file)

def response_color(code):
	return None

def is_character_printable(s):
  ## This method returns true if a byte is a printable ascii character ##
  return all((ord(c) < 127) and (ord(c) >= 32) for c in s)
  
def validate_byte_as_printable(byte):
  ## Check if byte is a printable ascii character. If not replace with a '.' character ##
  if is_character_printable(byte):
    return byte
  else:
    return '.'

class Corkscrew:
	def __init__(self, url, options=None, args=None):
		self.url = url
		self.url_parts = urlparse(url, scheme=CORKSCREW_SCHEME)

		# Build request	
		self.request = Request(self.url,
			None,
			headers=CORKSCREW_HEADERS,
			method=CORKSCREW_DEFAULT_METHOD)

		# Save config
		self.options = options
		self.args = args

		# Command switcher
		self.cmd_switcher = {
			"GET": self.cmd_get,
			"POST": self.cmd_post,
			"OPTIONS": self.cmd_options,
			"SET": self.cmd_set,
			"EXIT": self.cmd_exit,
			# Alias to exit command
			"QUIT": self.cmd_exit,
			"REQUEST": self.cmd_request,
			"COOKIE": self.cmd_cookie,
			"HOST": self.cmd_host
		}

		self.cmd = "GET"
		
		# Cookie policy, jar, and opener
		policy = DefaultCookiePolicy(rfc2965=True,
			strict_ns_domain=DefaultCookiePolicy.DomainLiberal)

		self.cookie_jar = CookieJar(policy)
		self.opener = build_opener(HTTPCookieProcessor(self.cookie_jar))
	def _decode_jwt(self):
		# Future method for decoding Java Web Token (JWT) strings
		pass
	def _header_color(self, name):
		# Custom headers
		if name.startswith("X-"):
			c = colors.RED
		else:
			# Hightlight (General, entity, response, and representation) headers
			if name in CORKSCREW_GENERAL_HEADERS:
				c = colors.YELLOW
			elif name in CORKSCREW_ENTITY_HEADERS:
				c = colors.LIGHTGREEN
			elif name in CORKSCREW_RESPONSE_HEADERS:
				c = colors.BLUE
			elif name in CORKSCREW_REPR_HEADERS:
				c = colors.ENDC
			else:
				c = colors.ENDC

		# Return header color
		return c
	def _print_divider(self, chars=80):
		color_print(colors.DARKGRAY, "*" * chars)
	def _dump_hex(self, data):
		memory_address = 0
		ascii_string = ""

		# Output to hex/ascii
		for c in data:
			#ascii_string = ascii_string + validate_byte_as_printable(c)
			if (memory_address % 16) == 15:
				addr_end = "\n"
			else:
				addr_end = ""

			# Convert data byte to hex
			addr = format(c, "02x")

			# Ouptut hex conversion
			print("{} ".format(addr), end=addr_end)

			# ASCII output

			# Bump address
			memory_address = memory_address + 1

		print("")
	def _print_http_header(self, name, value):
		# Custom headers
		color_print(self._header_color(name), name, newline=False)

		print(": ", end="")

		# Check for JSON values
		if value.startswith("{"):
			print(json.dumps(json.loads(value),
				indent=2,
				sort_keys=True))
		else:
			print(value)
	def _print_http_headers(self, headers):
		for header,value in headers.items():
			self._print_http_header(header, value)
	def _print_http_body(self, body):
		decode_success = False

		# Attempt to decode text
		try:
			content_body = body.decode(CORKSCREW_CODEC)
		except UnicodeDecodeError as e:
			print(e)
			decode_success = False
		else:
			decode_success = True

		# Plain text, try JSON decode or just output as is
		if decode_success:
			# Check for JSON
			if(content_body.startswith("{")):
				content_body = json.dumps(json.loads(content_body),
					indent=2,
					sort_keys=True)
			else:
				# Don't attempt to parse as JSON, output limited plain text body
				content_body = content_body[:self.options.body_limit]
			
			# Print what we came up with
			print(content_body)
		else:
			# Unicode decode error, output to hex/ascii
			self._dump_hex(body)
	def _print_cookiejar(self):
		# Cycle through cookies in jar
		for cookie in self.cookie_jar:
			cookie_name = cookie.name
			cookie_text = "{} (domain: {}, expires: {}, secure: {})".format(
				cookie.value,
				cookie.domain,
				cookie.expires,
				cookie.secure)

			# Output cookie name, value, and other details
			color_print(colors.BLUE, cookie_name, newline=False)
			print(":", cookie_text)
	def _send_request(self):
		# Output request info
		request_method = self.request.method.upper()

		color_print(colors.GREEN, request_method, newline=False)
		print(" request to ", end="")
		color_print(colors.GREEN, self.request.full_url)

		# Output request headers
		self._print_http_headers(self.request.headers)

		# Output request data if any found
		if self.request.data:
			color_print(colors.GREEN, "Data:")
			print(self.request.data)

		# Try to send request
		try:
			with self.opener.open(self.request, timeout=30) as conn:
				# Read and save response
				self.response = conn.read()

				print("\nResponse from ", end="")
				color_print(colors.GREEN, conn.geturl())

				# Output response headers
				self._print_http_headers(conn.headers)

				# Output response body and status
				self._print_divider()
				self._print_http_body(self.response)
				self._print_divider()

				# Output status code and reason
				color_print(colors.CYAN, "{} {}".format(conn.status, conn.reason))
		except HTTPError as e:
			# Output error response
			print("\nResponse from ", end="")
			color_print(colors.RED, e.geturl())

			self._print_http_headers(e.headers)

			# Output divider, body, tatus code & reason
			self._print_divider()
			self._print_http_body(e.read())

			color_print(colors.RED, "{} {}".format(e.code, e.reason))
	# Commands
	def cmd_get(self, args=None):
		self.request.method = "GET"

		# Command arguments
		if args:
			# If not URI make new request with full URL
			if not args[0].startswith("/"):
				self.request = Request(args[0],
					None,
					headers=CORKSCREW_HEADERS,
					method="GET")
			else:
				# Update selector with user provided
				self.request.selector = args[0]

		# Send GET
		self._send_request()
	def cmd_post(self, args=None):
		# Change to POST and send request
		self.request.method = "POST"

		# User supplied arguments
		if args:
			# Update selector with user provided
			self.request.selector = args[0]
			
			# Path to content file provided via arguments
			if len(args) == 2:
				content_path = os.path.abspath(args[1])

				# Check if content file exists
				if file_exists(content_path):
					color_print(colors.GREEN, "Using '{}' for POST data".format(content_path))

					# Open file and add content as request data
					with open(content_path, "rb") as f:
						content = f.read()
						self.request.data = content

		# Send POST
		self._send_request()
	def cmd_patch(self, args=None):
		None
	def cmd_update(self, args=None):
		None
	def cmd_options(self, args=None):
		None
	def cmd_exit(self, args=None):
		print("like tears in rain...")

		sys.exit(0)
	def cmd_cookie(self, args=None):
		# Cookies
		num_cookies = len(self.cookie_jar)

		if num_cookies > 0:
			if args:
				cookie_name = args[0]

				for cookie in self.cookie_jar:
					if cookie_name == cookie.name:
						print(cookie.value)
						return
			else:
				print("Cookies ({}):".format(num_cookies))
				self._print_cookiejar()
	def cmd_request(self, args=None):
		# No arguments, output current request information
		if args == None:
			color_print(colors.GREEN, "Request (current):")

			print("Scheme:", self.request.type)
			print("Host:", self.request.host)
			print("Method:", self.request.get_method())
			print("URI:", self.request.selector, "\n")

			num_headers = len(self.request.headers)
			print("Headers ({}):".format(num_headers))

			# List request headers
			self._print_http_headers(self.request.headers)

			# Mmmm... cookies
			num_cookies = len(self.cookie_jar)
			
			if num_cookies > 0:
				print("\nCookies ({}):".format(num_cookies))
				self._print_cookiejar()
		else:
			# Set new host
			self.request.host = args[0]
	def cmd_set(self, args=None):
		# Output current options
		if not args:
			color_print(colors.GREEN, "Current app options:")
			print("\nInsecure:", self.options.insecure)
		else:
			# If variable name and value provided try to update
			if (len(args) == 2):
				name = args[0]
				value = args[1]

				print("Set {} to {}".format(name, value))
	def cmd_host(self, args=None):
		if args:
			new_host = args[0]

			# Hostname validation?
			self.request.host = new_host

			color_print(colors.GREEN, "Host set to {}".format(new_host))
		else:
			print("Host:", self.request.host)
	def run_cmd(self, cmd):
		if cmd != ".":
			self.cmd = cmd

		# Return method or None
		return self.cmd_switcher.get(self.cmd.upper(), None)
	def prompt(self):
		line = ""

		# Prompt loop		
		while True:
			our_prompt = CORKSCREW_PROMPT.format(self.cmd, self.request.host)
			line = input(our_prompt)
			line_split = line.split()
			
			# Skip empty lines	
			if (len(line_split) == 0 or not line_split[0]):	
				continue
			
			# Collect command name and arguments
			cmd = line_split[0].upper()
			args = line_split[1:]

			# If no arguments set to None
			if len(args) == 0:
				args = None

			# Run function if one is found for command
			func = self.run_cmd(cmd)
			
			if func is not None:
				func(args)
