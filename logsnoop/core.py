"""
Core log parser engine that coordinates with plugins and database.
"""

import os
import json
import hashlib
import importlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from .database import LogDatabase
from .plugins.base import BaseLogPlugin


class LogParser:
    """Main log parser engine."""
    
    def __init__(self, db_path: str = "logsnoop.db"):
        """Initialize the log parser with database path."""
        self.db = LogDatabase(db_path)
        self.plugins: Dict[str, BaseLogPlugin] = {}
        self._load_plugins()
    
    def _load_plugins(self):
        """Load all available plugins."""
        plugins_dir = os.path.join(os.path.dirname(__file__), 'plugins')
        
        # Get all Python files in plugins directory
        for filename in os.listdir(plugins_dir):
            if filename.endswith('.py') and not filename.startswith('__') and filename != 'base.py':
                plugin_name = filename[:-3]  # Remove .py extension
                
                try:
                    # Import the plugin module
                    module = importlib.import_module(f'.plugins.{plugin_name}', package='logsnoop')
                    
                    # Look for plugin class (should end with 'Plugin')
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, BaseLogPlugin) and 
                            attr != BaseLogPlugin):
                            
                            plugin_instance = attr()
                            self.plugins[plugin_instance.name] = plugin_instance
                            print(f"Loaded plugin: {plugin_instance.name}")
                            break
                            
                except Exception as e:
                    print(f"Failed to load plugin {plugin_name}: {e}")
    
    def get_available_plugins(self) -> List[str]:
        """Get list of available plugin names."""
        return list(self.plugins.keys())
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def parse_log_file(self, file_path: str, plugin_name: str) -> Dict[str, Any]:
        """Parse a log file using the specified plugin."""
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin '{plugin_name}' not found")
        
        # Check if file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        # Calculate file hash to check for duplicates
        file_hash = self._calculate_file_hash(file_path)
        existing_file = self.db.get_file_by_hash(file_hash)
        
        if existing_file:
            print(f"File already parsed (duplicate detected): {existing_file['file_path']}")
            return {
                'file_id': existing_file['id'],
                'entries_count': len(self.db.get_entries_by_file(existing_file['id'])),
                'summary': self.db.get_summary(existing_file['id']),
                'duplicate': True
            }
        
        plugin = self.plugins[plugin_name]
        
        # Parse the log file
        content = ""
        line_count = 0
        
        # Check if this is a binary plugin that needs special handling
        if hasattr(plugin, 'parse_binary_file') and callable(getattr(plugin, 'parse_binary_file', None)):
            # Plugin can handle binary files directly
            parsed_data = getattr(plugin, 'parse_binary_file')(file_path)
            line_count = parsed_data.get('summary', {}).get('total_entries', 0)
        else:
            # Standard text file parsing
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            parsed_data = plugin.parse(content)
            line_count = len(content.splitlines())
        
        # Store results in database
        file_record = {
            'file_path': file_path,
            'plugin_name': plugin_name,
            'parsed_at': datetime.now().isoformat(),
            'file_size': os.path.getsize(file_path),
            'line_count': line_count,
            'file_hash': file_hash
        }
        
        file_id = self.db.store_file_info(file_record)
        
        # Store parsed entries
        for entry in parsed_data.get('entries', []):
            entry['file_id'] = file_id
            self.db.store_log_entry(entry)
        
        # Store summary statistics
        summary = parsed_data.get('summary', {})
        summary['file_id'] = file_id
        self.db.store_summary(summary)
        
        return {
            'file_id': file_id,
            'entries_count': len(parsed_data.get('entries', [])),
            'summary': summary
        }
    
    def query_logs(self, plugin_name: str, query_type: str, **kwargs) -> Any:
        """Execute a query using the specified plugin."""
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin '{plugin_name}' not found")
        
        plugin = self.plugins[plugin_name]
        
        # Get data from database for this plugin
        file_id = kwargs.pop('file_id', None)  # Remove file_id from kwargs before passing to plugin
        if file_id:
            # Query specific file
            log_entries = self.db.get_entries_by_file(file_id)
        else:
            # Query all files for this plugin
            log_entries = self.db.get_entries_by_plugin(plugin_name)
        
        # Execute the query
        return plugin.query(query_type, log_entries, **kwargs)
    
    def get_file_summary(self, file_id: int) -> Optional[Dict[str, Any]]:
        """Get summary for a specific file."""
        return self.db.get_summary(file_id)
    
    def list_parsed_files(self) -> List[Dict[str, Any]]:
        """List all parsed files."""
        return self.db.get_all_files()