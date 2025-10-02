"""
SSH Authentication Log Plugin
Parses SSH authentication logs (auth.log, secure, etc.)
"""

import re
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict
from .base import BaseLogPlugin


class SSHAuthPlugin(BaseLogPlugin):
    """Plugin for parsing SSH authentication logs."""
    
    @property
    def name(self) -> str:
        return "ssh_auth"
    
    @property
    def description(self) -> str:
        return "Parser for SSH authentication logs (auth.log, secure)"
    
    @property
    def supported_queries(self) -> List[str]:
        return [
            "failed_logins",
            "successful_logins", 
            "connection_count",
            "suspicious_logins",
            "top_attackers",
            "login_attempts_by_user",
            "connections_by_ip"
        ]
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        """Parse SSH authentication log content."""
        lines = log_content.strip().split('\n')
        entries = []
        stats = defaultdict(int)
        
        # Regex patterns for different SSH log events
        patterns = {
            'connection': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:\s+Connection from ([0-9.]+) port (\d+)',
            'failed_password': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:\s+Failed password for (\w+) from ([0-9.]+) port (\d+)',
            'accepted_password': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:\s+Accepted password for (\w+) from ([0-9.]+) port (\d+)',
            'disconnect': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:\s+Received disconnect from ([0-9.]+)',
            'invalid_user': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:\s+Invalid user (\w+) from ([0-9.]+)',
            'server_listening': r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:\s+Server listening on ([0-9.:]+) port (\d+)'
        }
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
                
            entry = {
                'line_number': line_num,
                'raw_line': line,
                'timestamp': None,
                'hostname': None,
                'pid': None,
                'ip_address': None,
                'port': None,
                'username': None,
                'event_type': 'unknown',
                'status': None
            }
            
            # Try to match against each pattern
            matched = False
            for event_type, pattern in patterns.items():
                match = re.search(pattern, line)
                if match:
                    matched = True
                    entry['event_type'] = event_type
                    entry['timestamp'] = self.normalize_timestamp(match.group(1))
                    entry['hostname'] = match.group(2)
                    entry['pid'] = int(match.group(3))
                    
                    if event_type == 'connection':
                        entry['ip_address'] = match.group(4)
                        entry['port'] = int(match.group(5))
                        entry['status'] = 'connection'
                        stats['total_connections'] += 1
                        
                    elif event_type == 'failed_password':
                        entry['username'] = match.group(4)
                        entry['ip_address'] = match.group(5)
                        entry['port'] = int(match.group(6))
                        entry['status'] = 'failed'
                        stats['failed_logins'] += 1
                        
                    elif event_type == 'accepted_password':
                        entry['username'] = match.group(4)
                        entry['ip_address'] = match.group(5)
                        entry['port'] = int(match.group(6))
                        entry['status'] = 'success'
                        stats['successful_logins'] += 1
                        
                    elif event_type == 'disconnect':
                        entry['ip_address'] = match.group(4)
                        entry['status'] = 'disconnect'
                        stats['disconnections'] += 1
                        
                    elif event_type == 'invalid_user':
                        entry['username'] = match.group(4)
                        entry['ip_address'] = match.group(5)
                        entry['status'] = 'invalid_user'
                        stats['invalid_users'] += 1
                        
                    elif event_type == 'server_listening':
                        entry['ip_address'] = match.group(4)
                        entry['port'] = int(match.group(5))
                        entry['status'] = 'server_start'
                        stats['server_starts'] += 1
                    
                    break
            
            if not matched:
                # Try to extract basic info even if pattern doesn't match
                basic_match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+sshd\[(\d+)\]:', line)
                if basic_match:
                    entry['timestamp'] = self.normalize_timestamp(basic_match.group(1))
                    entry['hostname'] = basic_match.group(2)
                    entry['pid'] = int(basic_match.group(3))
            
            if self.validate_entry(entry):
                entries.append(entry)
        
        # Calculate additional statistics
        unique_ips = set(entry.get('ip_address') for entry in entries if entry.get('ip_address'))
        unique_users = set(entry.get('username') for entry in entries if entry.get('username'))
        
        stats.update({
            'total_entries': len(entries),
            'unique_ips': len(unique_ips),
            'unique_users': len(unique_users)
        })
        
        return {
            'entries': entries,
            'summary': dict(stats)
        }
    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        """Execute queries on SSH log entries."""
        
        if query_type == "failed_logins":
            failed = [entry for entry in log_entries if entry.get('status') == 'failed']
            if kwargs.get('by_ip'):
                ip_counts = defaultdict(int)
                for entry in failed:
                    if entry.get('ip_address'):
                        ip_counts[entry['ip_address']] += 1
                return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))
            return failed
        
        elif query_type == "successful_logins":
            return [entry for entry in log_entries if entry.get('status') == 'success']
        
        elif query_type == "connection_count":
            connections = [entry for entry in log_entries if entry.get('event_type') == 'connection']
            if kwargs.get('by_ip'):
                ip_counts = defaultdict(int)
                for entry in connections:
                    if entry.get('ip_address'):
                        ip_counts[entry['ip_address']] += 1
                return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))
            return len(connections)
        
        elif query_type == "suspicious_logins":
            # Find successful logins with no subsequent activity
            successful = [entry for entry in log_entries if entry.get('status') == 'success']
            suspicious = []
            
            for login in successful:
                ip = login.get('ip_address')
                timestamp = login.get('timestamp')
                
                # Look for any activity after this login from same IP
                has_activity = False
                for other_entry in log_entries:
                    other_timestamp = other_entry.get('timestamp')
                    if (other_entry.get('ip_address') == ip and 
                        timestamp and other_timestamp and other_timestamp > timestamp and
                        other_entry.get('event_type') not in ['disconnect']):
                        has_activity = True
                        break
                
                if not has_activity:
                    suspicious.append(login)
            
            return suspicious
        
        elif query_type == "top_attackers":
            limit = kwargs.get('limit', 10)
            failed = [entry for entry in log_entries if entry.get('status') == 'failed']
            ip_counts = defaultdict(int)
            
            for entry in failed:
                if entry.get('ip_address'):
                    ip_counts[entry['ip_address']] += 1
            
            return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit])
        
        elif query_type == "login_attempts_by_user":
            user = kwargs.get('username')
            if user:
                return [entry for entry in log_entries if entry.get('username') == user]
            else:
                user_counts = defaultdict(int)
                for entry in log_entries:
                    if entry.get('username') and entry.get('status') in ['failed', 'success']:
                        user_counts[entry['username']] += 1
                return dict(sorted(user_counts.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "connections_by_ip":
            ip = kwargs.get('ip_address')
            if ip:
                return [entry for entry in log_entries if entry.get('ip_address') == ip]
            else:
                ip_counts = defaultdict(int)
                for entry in log_entries:
                    if entry.get('ip_address'):
                        ip_counts[entry['ip_address']] += 1
                return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))
        
        else:
            raise ValueError(f"Unsupported query type: {query_type}")
    
    def normalize_timestamp(self, timestamp_str: str) -> str:
        """Normalize SSH log timestamp to ISO format."""
        try:
            # SSH logs typically use format like "Oct 11 10:12:00"
            # Add current year since it's not in the log
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            return dt.isoformat()
        except ValueError:
            # If parsing fails, return original string
            return timestamp_str