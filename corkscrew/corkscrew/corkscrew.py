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
from urllib.request import urlopen, Request
from urllib.error import HTTPError

CORKSCREW_VERSION = "0.1"
CORKSCREW_PROMPT = "corkscrew> "
# Default protocol scheme
CORKSCREW_SCHEME = "https"
CORKSCREW_AUTHOR = "Jonathan Cormier"

CORKSCREW_HEADERS = {
	"User-Agent": "Corkscrew/" + CORKSCREW_VERSION,
	"Accept": "text/*,application/xhtml+xml,application/xml,application/json,application/ld+json",
	#"Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.3",
	#"Accept-Encoding": "none"k,
	#"Accept-Language": "en-US,en;q=0.8",
	"Connection": "keep-alive"
}

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

# Response codes
# CORKSCREW_RESPONSE_CODES = {
# 	# 1xx  Informational Response
# 	100: "Continue",
# 	101: "Switching Protocols",
# 	103: "Early Hints",
# 	# 2xx Successful
# 	200: "OK",
# 	201: "Created",
# 	202: "Accepted",
# 	203: "Non-Authoritative Information",
# 	204: "No Content",
# 	205: "Reset Content",
# 	206: "Partial Content",
# 	# 3xx Redirection
# 	300: "Multiple Choices",
# 	301: "Moved Permanently",
# 	302: "Found",
# 	303: "See Other",
# 	304: "Not Specified",
# 	307: "Temporary Redirect",
# 	308: "Permanent Redirect",
# 	# 4xx Client Error
# 	400: "Bad Request",
# 	401: "Unauthorized",
# 	402: "Payment Required",
# 	403: "Forbidden",
# 	404: "Not Found",
# 	405: "Method Not Allowed",
# 	406: "Not Acceptable",
# 	407: "Proxy Authentication Required",
# 	408: "Request Timeout",
# 	409: "Conflict",
# 	410: "Gone",
# 	411: "Length Required",
# 	412: "Precondition Failed",
# 	413: "Payload Too Large",
# 	414: "URI Too Long",
# 	415: "Unsupported Media Type",
# 	416: "Range Not Satisfiable",
# 	417: "Expectation Failed",
# 	418: "I'm a teapot",
# 	422: "Unprocessable Entity",
# 	425: "Too Early",
# 	426: "Upgrade Required",
# 	428: "Precondition Required",
# 	429: "Too Many Requests",
# 	431: "Request Header Fields Too Large",
# 	451: "Unavailable For Legal Reasons",
# 	# 5xx Server Error
# 	500: "Internal Server Error",
# 	501: "Not Implemented",
# 	502: "Bad Gateway",
# 	503: "Service Unavailable",
# 	504: "Gateway Timeout",
# 	505: "HTTP Version Not Supported",
# 	506: "Variant Also Negotiates",
# 	507: "Insufficient Storage",
# 	508: "Loop Detected",
# 	510: "Not Extended",
# 	511: "Network Authentication Required"
# }

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
		self.request = Request(self.url, None, CORKSCREW_HEADERS)

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
			"COOKIE": self.cmd_cookie
		}

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
				c = colors.GREEN
			elif name in CORKSCREW_REPR_HEADERS:
				c = colors.ENDC
			else:
				c = colors.ENDC

		# Return header color
		return c
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
	def _list_current_headers(self, args=None):
		# Print current request header headers and their values
		for header,value in self.request.headers.items():
			print(header + ": " + value)
	def _print_http_header(self, name, value):
		# Custom headers
		color_print(self._header_color(name), name, newline=False)
		print(":", value)
	def _print_http_headers(self, headers):
		for header,value in headers.items():
			self._print_http_header(header, value)
	def _print_http_body(self, body):
		plain_text = True

		# Attempt to decode text as UTF-8
		try:
			content_body = body.decode('utf-8')
		except UnicodeDecodeError as _:
			plain_text = False

		# Plain text, try JSON decode or just output as is
		if plain_text:
			# Check for JSON
			if(content_body.startswith("{")):
				content_body = json.dumps(json.loads(content_body),
					indent=3,
					sort_keys=True)
			else:
				# Don't attempt to parse as JSON, output limited plain text body
				content_body = content_body[:self.options.body_limit]
			
			# Print what we came up with
			print(content_body)
		else:
			# Unicode decode error, output to hex/ascii
			self._dump_hex(body)

	# Commands
	def cmd_get(self, args=None):
		content_path = None

		# Command arguments
		if args:
			# If not URI make new request with full URL
			if not args[0].startswith("/"):
				self.request = Request(args[0], headers=CORKSCREW_HEADERS)
			else:
				# Update selector with user provided one
				self.request.selector = args[0]

			# User provided path to content file
			if len(args) == 2:
				content_path = os.path.abspath(args[1])

				# Check if content file exists
				if file_exists(content_path):
					color_print(colors.GREEN, "Loading file {} for request".format(content_path))

		# Send HTTP request
		try:
			with urlopen(self.request) as conn:
				color_print(colors.GREEN, "GET to {}...".format(self.request.host))

				# Output request headers
				color_print(colors.PURPLE, "Request:")
				self._print_http_headers(self.request.headers)

				# Read and decode response
				self.response = conn.read()
				
				# Output response headers
				color_print(colors.PURPLE, "Response:")
				self._print_http_headers(conn.headers)

				# Output response body and status
				color_print(colors.PURPLE, "+++")

				# Output HTTP body
				self._print_http_body(self.response)

				# Output HTTP status
				color_print(colors.CYAN, "{} {}".format(conn.status, conn.reason))
		except HTTPError as e:
			# Output HTTP error response headers
			color_print(colors.GREEN, "Response:")

			self._print_http_headers(e.headers)
			
			color_print(colors.PURPLE, "+++")
			color_print(colors.RED, "{} {}".format(e.code, e.reason))
	def cmd_post(self, args=None):
		color_print(colors.GREEN, "POST to {}...".format(self.request.host))
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
		pass
	def cmd_request(self, args=None):
		# No arguments, output current request information
		if args == None:
			color_print(colors.GREEN, "Request (current):")

			print("Host:", self.request.host)
			print("Method:", self.request.get_method())
			print("URI:", self.request.selector, "\n")
			print("Headers:")

			# List request headers
			self._list_current_headers()
		else:
			# Set new host
			self.request.host = args[0]
	def cmd_set(self, args=None):
		# Output current options
		if not args:
			color_print(colors.GREEN, "Current options:\n")

			print("Insecure:", self.options.insecure)
		else:
			# If variable name and value provided try to update
			if (len(args) == 2):
				name = args[0]
				value = args[1]

				print("Set {} to {}".format(name, value))
	def run_cmd(self, cmd):
		# Return method or None
		return self.cmd_switcher.get(cmd.upper(), None)
	def prompt(self):
		line = ""

		# Loop		
		while True:
			line = input(CORKSCREW_PROMPT)
			line_split = line.split()
			
			# Skip empty lines	
			if (len(line_split) == 0 or not line_split[0]):	
				continue
			
			# Collect command name and arguments
			cmd = line_split[0].upper()
			args = line_split[1:]

			if len(args) == 0:
				args = None

			# Run function
			func = self.run_cmd(cmd)
			
			if func is not None:
				func(args)