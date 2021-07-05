#!/usr/bin/python3
#
import os
import logging
from optparse import OptionParser, SUPPRESS_USAGE

# Path and SourceFileLoader for locating and loading modules
from pathlib import Path
from importlib.machinery import SourceFileLoader

# Abstract classes
from abc import ABC, abstractmethod

# AWS SDK
import boto3
from boto3.session import Session
from botocore.exceptions import ClientError

# Name of directory containing command modules
MYCMD_CMDS_DIRNAME = "cmds"

class MyCmdCommand(ABC):
	def __init__(self, name, args):
		self.name = name
		self.args = args

		super().__init__()

	@abstractmethod
	def handler(self, session, args=None):
		pass

class MyCmd:
	def __init__(self, cmd, cmd_args, conf, paths, log_level=logging.INFO, prog=None):
		self.cmd = cmd
		self.cmd_args = cmd_args
		self.prog = prog
		
		# Dictionary of commands
		self.cmds = {
			"hello": self._cmd_hello
		}
		
		# Save boto session
		self.session = Session()

		logging.basicConfig(format="%(message)s", level=log_level)
		self.log = logging.getLogger(__name__)

		# Load commands from external location
		self._load_commands(paths)
	def run(self):
		# Check for builtin command list
		if self.cmd.lower() == 'list':
			self._cmd_list()
		else:
			# Route command to proper loaded module
			try:
				cmd_func = self.cmds[self.cmd]

				# Run command if module was found
				if cmd_func:
					self._run_command(self.cmd, cmd_func, self.cmd_args)
			except KeyError as e:
				self.log.info(f"Command not found: {e}\n")
				self.log.info(f"Try 'list' to get availabe commands")

	def _load_commands(self, paths=None):
		# Loop through paths
		for path in paths:
			# Add 'cmds' directory to path
			cmd_dir = Path(path).joinpath(MYCMD_CMDS_DIRNAME)
			# Expand and resolve path
			cmd_dir_full = cmd_dir.expanduser().resolve()
			
			self.log.debug(f"Loading commands in: {cmd_dir_full}")

			# Loop through command directories
			for (dirpath, dirnames, _) in os.walk(cmd_dir_full):
				# Loop through command directory names
				for dirname in dirnames:
					self._load_command(dirname, dirpath)
	def _load_command(self, name, path):
		# Build path to command module
		cmd_path = Path(path).joinpath(name)

		self.log.debug(f"Found command '{name}' at {cmd_path}")

		# Load command

		# Store in local
	def _list_commands(self, verbose=False):
		self.log.info(f"Available commands:")

		# Loop through loaded commands
		for cmd in self.cmds:
			self.log.info(cmd)
	def _cmd_list(self):
		self.log.debug(f"List command argument(s): {self.cmd_args}")

		# Create parser for list command
		parser = OptionParser(usage=SUPPRESS_USAGE)
		parser.add_option("-d", "--detail", action="count", help="Include additional command detail")

		# Parse list arguments
		(opts, _) = parser.parse_args(args=self.cmd_args)

		# List commands with user set detail
		self._list_commands(opts.detail)
	def _cmd_hello(self):
		print("Hellloo developers!")
	def _run_command(self, name, cmd, args=None):
		self.log.debug(f"Running command {name}")
		self.log.debug(f"Command argument(s): {args}")

		cmd()

		self.log.debug(f"End of {name}")