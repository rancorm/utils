
import os
from optparse import OptionParser
import sys

from signal import signal, SIGINT
from corkscrew import Corkscrew

CORKSCREW_VERSION = "0.1"
CORKSCREW_SCHEME = "https"
CORKSCREW_AUTHOR = "Jonathan Cormier"

# if sys.version_info < (3, 0):
#     string_type = basestring

#     if os.name != 'nt':
#         import codecs
#         UTF8Writer = codecs.getwriter('utf8')
#         sys.stdout = UTF8Writer(sys.stdout)
# else:
#     string_type = str

parser = OptionParser()
parser.add_option("--insecure", action="store_false", dest="insecure", default=False, help="don't verify security certificates")
parser.add_option("--body-limit", action="store_false", dest="body_limit", default=2048, help="limit content body output (default: 2048)")
parser.add_option("--only-headers", action="store_true", dest="only_headers", default=False, help="Output only HTTP headers")

(options, args) = parser.parse_args()

# Interrupt handlers
def ctrlc(signal_received, frame):
	sys.exit(0)

# Setup signal handlers
signal(SIGINT, ctrlc)

# Check for host on command line, set to localhost if not found
if (len(sys.argv) >= 2):
    user_url = sys.argv[-1]
else:
    user_url = "http://localhost"

print("Welcome to Corkscrew v{} by {}"
    .format(CORKSCREW_VERSION, CORKSCREW_AUTHOR))

cs = Corkscrew(user_url, options, args)
cs.prompt()
