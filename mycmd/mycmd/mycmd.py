#!/usr/bin/python3
#
import os
import logging
from optparse import OptionParser, SUPPRESS_USAGE

# Path and SourceFileLoader for locating and loading modules
from pathlib import Path
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_file_location, module_from_spec, spec_from_loader

# AWS SDK
import boto3
from boto3.session import Session
from botocore.exceptions import ClientError

# Name of directory containing command modules
MYCMD_CMDS_DIRNAME = "cmds"

class MyCmd:
	def __init__(self, cmd, cmd_args, conf, paths, log_level=logging.WARN, prog=None):
		self.cmd = cmd
		self.cmd_args = cmd_args
		self.prog = prog
		
		# Dictionary of commands
		self.cmds = {}

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
				# Get handler function
				cmd_func = self.cmds[self.cmd].handler

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
			try:
				with os.scandir(cmd_dir_full) as it:
					for entry in it:
						if entry.is_dir:
							entry_name = entry.name

							# Check if command with name is already loaded to hash
							if entry_name not in self.cmds:
								self._load_command(entry_name, cmd_dir_full)
							else:
								self.log.debug(f"Command with name '{entry_name}' already exists, skipping...")
			except FileNotFoundError as _:
				pass
	def _load_command(self, name, path):
		# Build path to command module
		cmd_path = Path(path).joinpath(name)
		cmd_path_2 = cmd_path.joinpath(name + ".py")

		self.log.debug(f"Loading command '{name}' at {cmd_path}")

		# Load command module
		spec = spec_from_file_location(name, cmd_path_2)
		mod = module_from_spec(spec)
		spec.loader.exec_module(mod)

		# Init and store in local
		command = mod.Command()
		# Store command name and handler reference in commands dictionary

		self.cmds.update({ name: command })
	def _list_commands(self, verbose=False):
		self.log.info(f"NAME\t\tDESCRIPTION")

		# Loop through loaded commands
		for cmd in self.cmds:
			# Look for command description
			try:
				desc = self.cmds[cmd].desc
			except AttributeError as _:
				desc = ""

			# Output command information
			self.log.info(f"{cmd}\t\t{desc}")
	def _cmd_list(self):
		self.log.debug(f"List command argument(s): {self.cmd_args}")

		# Create parser for list command
		parser = OptionParser(usage=SUPPRESS_USAGE)
		parser.add_option("-d", "--detail", action="count", help="Include additional command detail")

		# Parse list arguments
		(opts, _) = parser.parse_args(args=self.cmd_args)

		# List commands with user set detail
		self._list_commands(opts.detail)
	def _run_command(self, name, cmd, args=None):
		self.log.debug(f"Running command {name}")
		self.log.debug(f"Command argument(s): {args}")

		cmd(self.session)

		self.log.debug(f"End of {name}")