#!/usr/bin/python3
#
#
# SSHnoo.py [OpenSSH Session Snoop Tool]
#
# Usage: sshnoo.py PID
#
#
#from bcc import BPF

import argparse
import binascii

# Arguments
examples = """examples:
    ./sshnoo.py 181	    # Snoop on OpenSSH PID 181
    ./sshnoo.py -l	    # List current OpenSSH sessions
"""

parser = argparse.ArgumentParser(
    description="OpenSSH Session Snoop Tool",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-l", "--list", action="store_true", help="List current OpenSSH sessions") 
parser.add_argument("PID", nargs="?", type=int, help="OpenSSH PID to snoop")

args = parser.parse_args()

# eBPF SSH snoop program
bpf_text = """
example program
"""

# bp = BPF(text=bpf_text)
# bp.attach_uretprobe(name="/usr/sbin/sshd", sym="readline", fn_name="printret")

class SSHnoop:
	def __init__(self, pid):
		self.pid = pid
	def start(self):
		print("Running on", self.pid)
		
# Check arguments
if args.list:
	print("Current sessions:")
	

	# List
	 
else:
	if args.PID:
		sshnoop = SSHnoop(args.PID)
		sshnoop.start()
	else:
		parser.print_help()
