
import os
import sys
import logging
import platform
from optparse import OptionParser

from signal import signal, SIGINT

import boto3

from mycmd import MyCmd

# Configuration filename
MYCMD_CONF=".mycmdrc"
MYCMD_VERSION="0.1"

# Update file holds last time My CMD instance was updated
MYCMD_LAST_UPDATE="last-update"

# Application search paths
MYCMD_PATHS=[
	"~/.mycmd/",
	"/etc/mycmd/",
	"/usr/share/mycmd/"
]

# Name of environment variable for logging level
MYCMD_ENV_LOG="MYCMD_LOG"
MYCMD_ENV_NAME="MYCMD_NAME"

# Usage and epilog messages
MYCMD_USAGE = "Usage: %prog [OPTIONS] CMD [ARGS] [...]"
MYCMD_EPILOG = "Try 'list' for available commands."

# Get program name from environment or use default
try:
	our_name = os.environ[MYCMD_ENV_NAME]
except KeyError as _:
	our_name = sys.argv[0]

# Option parser
parser = OptionParser(usage=MYCMD_USAGE,
	prog=our_name,
	epilog=MYCMD_EPILOG)
# Disable interspersed argument parsing
parser.disable_interspersed_args()
# Add options to parser
parser.add_option("-r",
	"--refresh",
	action="store_true",
	default=False,
	help="pull latest from repository")
parser.add_option("-v",
	"--version",
	action="store_true",
	default=False,
	help="show version details")

# Parse command line arguments
(opts, args) = parser.parse_args()

# Interrupt handlers
def ctrlc(signal_received, frame):
	sys.exit(0)

# Setup signal handlers
signal(SIGINT, ctrlc)

# Check for command and arguments
if (len(args) >= 1):
	# Capture command and arguments
	cmd = args[0]
	cmd_args = args[1:]
else:
	# Check command line arguments
	if opts.version:
		print(f"MyCmd: {MYCMD_VERSION}")

		# Retrieve version information
		boto_version = boto3.__version__
		py_version = platform.python_version()
		plat = platform.platform(terse=True)

		print(f"Boto3: {boto_version}")
		print(f"Python: {py_version}")
		print(f"Platform: {plat}")
	elif opts.refresh:
		print("Pulling new commands from X")
	else:
		parser.print_help()

	sys.exit(0)

# Check environment variable for logging level
try:
	logging_level = os.environ[MYCMD_ENV_LOG]
except KeyError as e:
	logging_level = logging.INFO

# Start mycmd with arguments and options
cmd = MyCmd(cmd,
	cmd_args,
	MYCMD_CONF,
	MYCMD_PATHS,
	logging_level,
	our_name)

cmd.run()
