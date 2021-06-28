import os
from optparse import OptionParser
import sys

from signal import signal, SIGINT
from mycmd import MyCmd

# MyCmd configuration paths
MYCMD_PATHS=[
	"~/.mycmd/",
	"/etc/mycmd/",
	"/usr/share/mycmd/"
]

# if sys.version_info < (3, 0):
#     string_type = basestring

#     if os.name != 'nt':
#         import codecs
#         UTF8Writer = codecs.getwriter('utf8')
#         sys.stdout = UTF8Writer(sys.stdout)
# else:
#     string_type = str

parser = OptionParser()
#parser.add_option("--insecure", action="store_false", dest="insecure", default=False, help="don't verify security certificates")
#parser.add_option("--body-limit", action="store_false", dest="body_limit", default=2048, help="limit content body output (default: 2048)")

(opts, args) = parser.parse_args()

# Interrupt handlers
def ctrlc(signal_received, frame):
	sys.exit(0)

# Setup signal handlers
signal(SIGINT, ctrlc)

our_name = sys.argv[0]

# Check for host on command line, set to localhost if not found
if (len(sys.argv) >= 2):
	# Capture command and arguments
	cmd = sys.argv[1]
	cmd_args = sys.argv[1:]
else:
	print(f"Usage: {our_name:s} <cmd> [args] [...]")

	sys.exit(0)

# Start mycmd with arguments and options
cmd = MyCmd(cmd,
	cmd_args,
	MYCMD_PATHS,
	opts,
	args)
