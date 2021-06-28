#!/usr/bin/python3
#
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
	def __init__(self, cmd, cmd_args, paths=None, options=None, args=None):
		self.session = Session()

		self._load_commands(paths)
	def _load_commands(self, paths=None):
		print(f"Loading commands from path(s): {paths}")
	def _path(self):
		pass