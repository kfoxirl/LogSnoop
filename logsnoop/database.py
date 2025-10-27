"""
Flat file database implementation for storing log parsing results.
Uses JSON for simple storage and retrieval.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional


class LogDatabase:
    """Simple flat file database using JSON."""
    
    def __init__(self, db_path: str):
        """Initialize database with file path."""
        self.db_path = db_path
        self.data = {
            'files': [],
            'entries': [],
            'summaries': []
        }
        self._load_database()
    
    def _load_database(self):
        """Load existing database or create new one."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load database {self.db_path}: {e}")
                print("Starting with empty database")
        
        # Ensure all required keys exist
        for key in ['files', 'entries', 'summaries']:
            if key not in self.data:
                self.data[key] = []
    
    def _save_database(self):
        """Save database to file."""
        try:
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
        except IOError as e:
            print(f"Error saving database: {e}")
    
    def store_file_info(self, file_record: Dict[str, Any]) -> int:
        """Store file information and return file ID."""
        file_id = len(self.data['files']) + 1
        file_record['id'] = file_id
        self.data['files'].append(file_record)
        self._save_database()
        return file_id
    
    def store_log_entry(self, entry: Dict[str, Any]):
        """Store a parsed log entry."""
        entry_id = len(self.data['entries']) + 1
        entry['id'] = entry_id
        self.data['entries'].append(entry)
        self._save_database()

    def store_log_entries_bulk(self, entries: List[Dict[str, Any]], file_id: int, progress_every: int = 5000):
        """Store many parsed log entries efficiently with a single save.

        Assigns incremental IDs, sets file_id per entry, appends to DB, and writes once at the end.
        Prints periodic progress if LOGSNOOP_DEBUG is set.
        """
        import os, time
        debug = os.environ.get('LOGSNOOP_DEBUG', '0') == '1'
        start = time.time()
        next_id = len(self.data['entries']) + 1
        total = len(entries)
        for i, e in enumerate(entries, start=1):
            e['file_id'] = file_id
            e['id'] = next_id
            next_id += 1
            self.data['entries'].append(e)
            if debug and (i % max(1, progress_every) == 0):
                elapsed = time.time() - start
                print(f"[DEBUG] DB wrote {i}/{total} entries ({i/total*100:.1f}%) in {elapsed:.1f}s")
        self._save_database()
        if debug:
            print(f"[DEBUG] DB bulk save complete for {total} entries in {time.time() - start:.2f}s")
    
    def store_summary(self, summary: Dict[str, Any]):
        """Store summary statistics for a file."""
        summary_id = len(self.data['summaries']) + 1
        summary['id'] = summary_id
        self.data['summaries'].append(summary)
        self._save_database()
    
    def get_entries_by_plugin(self, plugin_name: str) -> List[Dict[str, Any]]:
        """Get all entries parsed by a specific plugin."""
        # First get file IDs for this plugin
        file_ids = []
        for file_record in self.data['files']:
            if file_record.get('plugin_name') == plugin_name:
                file_ids.append(file_record['id'])
        
        # Then get entries for these files
        entries = []
        for entry in self.data['entries']:
            if entry.get('file_id') in file_ids:
                entries.append(entry)
        
        return entries
    
    def get_entries_by_file(self, file_id: int) -> List[Dict[str, Any]]:
        """Get all entries for a specific file."""
        return [entry for entry in self.data['entries'] if entry.get('file_id') == file_id]
    
    def get_summary(self, file_id: int) -> Optional[Dict[str, Any]]:
        """Get summary for a specific file."""
        for summary in self.data['summaries']:
            if summary.get('file_id') == file_id:
                return summary
        return None
    
    def get_all_files(self) -> List[Dict[str, Any]]:
        """Get all parsed files."""
        return self.data['files']
    
    def get_file_info(self, file_id: int) -> Optional[Dict[str, Any]]:
        """Get information for a specific file."""
        for file_record in self.data['files']:
            if file_record.get('id') == file_id:
                return file_record
        return None
    
    def get_file_by_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get file record by hash to check for duplicates."""
        for file_record in self.data['files']:
            if file_record.get('file_hash') == file_hash:
                return file_record
        return None
    
    def query_entries(self, **filters) -> List[Dict[str, Any]]:
        """Query entries with filters."""
        entries = self.data['entries']
        
        for key, value in filters.items():
            if key == 'ip_address':
                entries = [e for e in entries if e.get('ip_address') == value]
            elif key == 'username':
                entries = [e for e in entries if e.get('username') == value]
            elif key == 'status':
                entries = [e for e in entries if e.get('status') == value]
            elif key == 'file_id':
                entries = [e for e in entries if e.get('file_id') == value]
            elif key == 'event_type':
                entries = [e for e in entries if e.get('event_type') == value]
        
        return entries