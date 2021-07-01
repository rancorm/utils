import os
from optparse import OptionParser
import sys
import logging

from signal import signal, SIGINT
from mycmd import MyCmd

# My CMD install path
MYCMD_ROOT="~/.mycmd/"
MYCMD_VERSION="0.1"

# My CMD configuration paths
MYCMD_PATHS=[
	"~/.mycmd/",
	"/etc/mycmd/",
	"/usr/share/mycmd/"
]

# Update file holds last time My CMD instance was updated
MYCMD_LAST_UPDATE="last-update"

# if sys.version_info < (3, 0):
#     string_type = basestring

#     if os.name != 'nt':
#         import codecs
#         UTF8Writer = codecs.getwriter('utf8')
#         sys.stdout = UTF8Writer(sys.stdout)
# else:
#     string_type = str

parser = OptionParser()
parser.add_option("--refresh", action="store_true", default=False, help="pull latest commands from repository")
parser.add_option("--version", action="store_true", default=False, help="show version")

(opts, args) = parser.parse_args()

# Interrupt handlers
def ctrlc(signal_received, frame):
	sys.exit(0)

# Setup signal handlers
signal(SIGINT, ctrlc)

our_name = sys.argv[0]

# Check for host on command line, set to localhost if not found
if (len(args) >= 1):
	# Capture command and arguments
	cmd = args[0]
	cmd_args = args[1:]
else:
	# Check command line arguments
	if opts.version:
		print(f"App: {MYCMD_VERSION}")
	elif opts.refresh:
		print("Pulling new commands from X")
	else:
		print(f"Usage: {our_name:s} [--version] [--refresh] <cmd> [args] [...]\n")
		print("Try 'list' or 'help' commands to get started")

	sys.exit(0)

# Check environment variable for logging level
try:
	logging_level = os.environ["MYCMD_LOG"]
except KeyError as e:
	logging_level = logging.INFO

# Start mycmd with arguments and options
cmd = MyCmd(cmd,
	cmd_args,
	MYCMD_PATHS,
	opts,
	args,
	logging_level)
