"""
Simple Login Log Plugin
Parses simple login logs with timestamp, IP, and username format
"""

import re
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict
from .base import BaseLogPlugin


class SimpleLoginPlugin(BaseLogPlugin):
    """Plugin for parsing simple login logs."""
    
    @property
    def name(self) -> str:
        return "simple_login"
    
    @property
    def description(self) -> str:
        return "Parser for simple login logs (timestamp IP username format)"
    
    @property
    def supported_queries(self) -> List[str]:
        return [
            "logins_by_user",
            "logins_by_ip",
            "login_count",
            "unique_users",
            "unique_ips",
            "login_timeline",
            "frequent_users",
            "frequent_ips"
        ]
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        """Parse simple login log content."""
        lines = log_content.strip().split('\n')
        entries = []
        stats = defaultdict(lambda: 0)
        
        # Pattern for simple login logs: "2011-03-04 15:52:36\t110.34.65.22\tsospipi"
        log_pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+([0-9.]+)\s+(\w+)'
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
                
            entry = {
                'line_number': line_num,
                'raw_line': line,
                'timestamp': None,
                'ip_address': None,
                'username': None,
                'event_type': 'login',
                'status': 'success'
            }
            
            match = re.search(log_pattern, line)
            if match:
                entry['timestamp'] = self.normalize_timestamp(match.group(1))
                entry['ip_address'] = match.group(2)
                entry['username'] = match.group(3)
                
                # Update statistics
                stats['total_logins'] += 1
                stats[f'user_{entry["username"]}'] += 1
                stats[f'ip_{entry["ip_address"]}'] += 1
            
            if self.validate_entry(entry):
                entries.append(entry)
        
        # Calculate additional statistics
        unique_ips = set(entry.get('ip_address') for entry in entries if entry.get('ip_address'))
        unique_users = set(entry.get('username') for entry in entries if entry.get('username'))
        
        additional_stats = {
            'total_entries': len(entries),
            'unique_ips': len(unique_ips),
            'unique_users': len(unique_users)
        }
        
        # Merge stats
        final_stats = dict(stats)
        final_stats.update(additional_stats)
        
        return {
            'entries': entries,
            'summary': final_stats
        }
    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        """Execute queries on simple login log entries."""
        
        if query_type == "logins_by_user":
            username = kwargs.get('username')
            if username:
                return [entry for entry in log_entries if entry.get('username') == username]
            else:
                user_counts = defaultdict(int)
                for entry in log_entries:
                    if entry.get('username'):
                        user_counts[entry['username']] += 1
                return dict(sorted(user_counts.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "logins_by_ip":
            ip_address = kwargs.get('ip_address')
            if ip_address:
                return [entry for entry in log_entries if entry.get('ip_address') == ip_address]
            else:
                ip_counts = defaultdict(int)
                for entry in log_entries:
                    if entry.get('ip_address'):
                        ip_counts[entry['ip_address']] += 1
                return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "login_count":
            return len(log_entries)
        
        elif query_type == "unique_users":
            users = set(entry.get('username') for entry in log_entries if entry.get('username'))
            return list(users)
        
        elif query_type == "unique_ips":
            ips = set(entry.get('ip_address') for entry in log_entries if entry.get('ip_address'))
            return list(ips)
        
        elif query_type == "login_timeline":
            # Group logins by time period
            period = kwargs.get('period', 'hour')  # hour, day, month
            timeline = defaultdict(int)
            
            for entry in log_entries:
                timestamp = entry.get('timestamp')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        
                        if period == 'hour':
                            key = dt.strftime('%Y-%m-%d %H:00')
                        elif period == 'day':
                            key = dt.strftime('%Y-%m-%d')
                        elif period == 'month':
                            key = dt.strftime('%Y-%m')
                        else:
                            key = timestamp
                        
                        timeline[key] += 1
                    except:
                        continue
            
            return dict(sorted(timeline.items()))
        
        elif query_type == "frequent_users":
            limit = kwargs.get('limit', 10)
            user_counts = defaultdict(int)
            
            for entry in log_entries:
                if entry.get('username'):
                    user_counts[entry['username']] += 1
            
            return dict(sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:limit])
        
        elif query_type == "frequent_ips":
            limit = kwargs.get('limit', 10)
            ip_counts = defaultdict(int)
            
            for entry in log_entries:
                if entry.get('ip_address'):
                    ip_counts[entry['ip_address']] += 1
            
            return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit])
        
        else:
            raise ValueError(f"Unsupported query type: {query_type}")
    
    def normalize_timestamp(self, timestamp_str: str) -> str:
        """Normalize simple login log timestamp to ISO format."""
        try:
            # Simple format: "2011-03-04 15:52:36"
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            # If parsing fails, return original string
            return timestamp_str