"""
Main entry point for LogSnoop
"""

from logsnoop.core import LogParser
from logsnoop.database import LogDatabase

__all__ = ['LogParser', 'LogDatabase']