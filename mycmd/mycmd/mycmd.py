#!/usr/bin/python3
#
import os
import logging
from pathlib import Path
from importlib.machinery import SourceFileLoader

# Abstract classes
from abc import ABC, abstractmethod

import boto3
from boto3.session import Session
from botocore.exceptions import ClientError

class MyCmdCmd(ABC):
	@abstractmethod
	def handler(self, args=None):
		pass

class MyCmd:
	def __init__(self, cmd, cmd_args, paths=None, options=None, args=None, log_level=logging.INFO):
		self.session = Session()

		logging.basicConfig(format="%(message)s", level=log_level)
		self.log = logging.getLogger(__name__)

		# Load commands from external location
		self._load_commands(paths)

		# Check for builtin commands list and help
		if cmd.lower() == 'list':
			self._cmd_list()
		elif cmd.lower() == 'help':
			self._cmd_help()

		# Route command to proper loaded module

	def _load_commands(self, paths=None):
		# Loop through paths
		for path in paths:
			# Add 'cmds' directory to path
			cmd_dir = Path(path).joinpath("cmds")
			# Expand and resolve path
			cmd_dir_full = cmd_dir.expanduser().resolve()
			
			self.log.debug(f"Loading commands found in: {cmd_dir_full}")

			# Loop through command directories
			for (dirpath, dirnames, filenames) in os.walk(cmd_dir_full):
				# Loop through command directory names
				for dirname in dirnames:
					self._load_command(dirname)
	def _load_command(self, path):
		self.log.debug(f"Loading command {path}")
	def _list_commands(self):
		self.log.info(f"Available commands on this system:")
	def _cmd_help(self):
		self.log.info(f"Detail help menu!")
	def _cmd_list(self):
		self._list_commands()