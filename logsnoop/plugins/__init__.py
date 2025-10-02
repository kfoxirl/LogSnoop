"""
Base plugin class that all log parser plugins must inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Union


class BaseLogPlugin(ABC):
    """Base class for all log parser plugins."""
    
    def __init__(self):
        """Initialize the plugin."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the plugin name."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Return the plugin description."""
        pass
    
    @property
    @abstractmethod
    def supported_queries(self) -> List[str]:
        """Return list of supported query types."""
        pass
    
    @abstractmethod
    def parse(self, log_content: str) -> Dict[str, Any]:
        """
        Parse log content and return structured data.
        
        Args:
            log_content: Raw log file content as string
            
        Returns:
            Dictionary with 'entries' (list of parsed log entries) and 'summary' (statistics)
        """
        pass
    
    @abstractmethod
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        """
        Execute a query on log entries.
        
        Args:
            query_type: Type of query to execute
            log_entries: List of parsed log entries
            **kwargs: Additional query parameters
            
        Returns:
            Query results (format depends on query type)
        """
        pass
    
    def validate_entry(self, entry: Dict[str, Any]) -> bool:
        """
        Validate a parsed log entry.
        
        Args:
            entry: Parsed log entry dictionary
            
        Returns:
            True if entry is valid, False otherwise
        """
        # Basic validation - ensure required fields exist
        required_fields = ['timestamp', 'raw_line']
        return all(field in entry for field in required_fields)
    
    def normalize_timestamp(self, timestamp_str: str) -> str:
        """
        Normalize timestamp to ISO format.
        Override in subclasses for specific timestamp formats.
        
        Args:
            timestamp_str: Raw timestamp string
            
        Returns:
            ISO formatted timestamp string
        """
        # Default implementation - return as-is
        # Subclasses should override this for proper timestamp parsing
        return timestamp_str