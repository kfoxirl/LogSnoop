"""
FTP Log Plugin
Parses FTP server logs (vsftpd, proftpd, etc.)
"""

import re
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict
from .base import BaseLogPlugin


class FTPLogPlugin(BaseLogPlugin):
    """Plugin for parsing FTP server logs."""
    
    @property
    def name(self) -> str:
        return "ftp_log"
    
    @property
    def description(self) -> str:
        return "Parser for FTP server logs (vsftpd, proftpd)"
    
    @property
    def supported_queries(self) -> List[str]:
        return [
            "uploads",
            "downloads", 
            "login_attempts",
            "failed_logins",
            "successful_logins",
            "bytes_transferred",
            "top_uploaders",
            "top_downloaders",
            "file_operations",
            "connections_by_ip"
        ]
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        """Parse FTP log content."""
        lines = log_content.strip().split('\n')
        entries = []
        stats = defaultdict(int)
        total_bytes_up = 0
        total_bytes_down = 0
        
        # Regex patterns for FTP log events (vsftpd format)
        patterns = {
            'connect': r'(\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+\[pid\s+(\d+)\]\s+CONNECT:\s+Client\s+"([^"]+)"',
            'login_ok': r'(\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+\[pid\s+(\d+)\]\s+\[([^\]]+)\]\s+OK\s+LOGIN:\s+Client\s+"([^"]+)"',
            'login_fail': r'(\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+\[pid\s+(\d+)\]\s+\[([^\]]+)\]\s+FAIL\s+LOGIN:\s+Client\s+"([^"]+)"',
            'upload': r'(\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+\[pid\s+(\d+)\]\s+\[([^\]]+)\]\s+OK\s+UPLOAD:\s+Client\s+"([^"]+)",\s+"([^"]+)",\s+(\d+)\s+bytes,\s+([0-9.]+)Kbyte/sec',
            'download': r'(\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+\[pid\s+(\d+)\]\s+\[([^\]]+)\]\s+OK\s+DOWNLOAD:\s+Client\s+"([^"]+)",\s+"([^"]+)",\s+(\d+)\s+bytes,\s+([0-9.]+)Kbyte/sec',
            'mkdir': r'(\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+\[pid\s+(\d+)\]\s+\[([^\]]+)\]\s+OK\s+MKDIR:\s+Client\s+"([^"]+)",\s+"([^"]+)"',
            'delete': r'(\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+\[pid\s+(\d+)\]\s+\[([^\]]+)\]\s+OK\s+DELETE:\s+Client\s+"([^"]+)",\s+"([^"]+)"'
        }
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
                
            entry = {
                'line_number': line_num,
                'raw_line': line,
                'timestamp': None,
                'pid': None,
                'username': None,
                'ip_address': None,
                'event_type': 'unknown',
                'status': None,
                'file_path': None,
                'bytes_transferred': 0,
                'transfer_speed': 0.0
            }
            
            # Try to match against each pattern
            matched = False
            for event_type, pattern in patterns.items():
                match = re.search(pattern, line)
                if match:
                    matched = True
                    entry['event_type'] = event_type
                    entry['timestamp'] = self.normalize_timestamp(match.group(1))
                    entry['pid'] = int(match.group(2))
                    
                    if event_type == 'connect':
                        entry['ip_address'] = match.group(3)
                        entry['status'] = 'connection'
                        stats['total_connections'] += 1
                        
                    elif event_type == 'login_ok':
                        entry['username'] = match.group(3)
                        entry['ip_address'] = match.group(4)
                        entry['status'] = 'success'
                        stats['successful_logins'] += 1
                        
                    elif event_type == 'login_fail':
                        entry['username'] = match.group(3)
                        entry['ip_address'] = match.group(4)
                        entry['status'] = 'failed'
                        stats['failed_logins'] += 1
                        
                    elif event_type == 'upload':
                        entry['username'] = match.group(3)
                        entry['ip_address'] = match.group(4)
                        entry['file_path'] = match.group(5)
                        entry['bytes_transferred'] = int(match.group(6))
                        entry['transfer_speed'] = float(match.group(7))
                        entry['status'] = 'success'
                        stats['total_uploads'] += 1
                        total_bytes_up += entry['bytes_transferred']
                        
                    elif event_type == 'download':
                        entry['username'] = match.group(3)
                        entry['ip_address'] = match.group(4)
                        entry['file_path'] = match.group(5)
                        entry['bytes_transferred'] = int(match.group(6))
                        entry['transfer_speed'] = float(match.group(7))
                        entry['status'] = 'success'
                        stats['total_downloads'] += 1
                        total_bytes_down += entry['bytes_transferred']
                        
                    elif event_type == 'mkdir':
                        entry['username'] = match.group(3)
                        entry['ip_address'] = match.group(4)
                        entry['file_path'] = match.group(5)
                        entry['status'] = 'success'
                        stats['directories_created'] += 1
                        
                    elif event_type == 'delete':
                        entry['username'] = match.group(3)
                        entry['ip_address'] = match.group(4)
                        entry['file_path'] = match.group(5)
                        entry['status'] = 'success'
                        stats['files_deleted'] += 1
                    
                    break
            
            if self.validate_entry(entry):
                entries.append(entry)
        
        # Calculate additional statistics
        unique_ips = set(entry.get('ip_address') for entry in entries if entry.get('ip_address'))
        unique_users = set(entry.get('username') for entry in entries if entry.get('username'))
        
        stats.update({
            'total_entries': len(entries),
            'unique_ips': len(unique_ips),
            'unique_users': len(unique_users),
            'total_bytes_uploaded': total_bytes_up,
            'total_bytes_downloaded': total_bytes_down,
            'total_bytes_transferred': total_bytes_up + total_bytes_down
        })
        
        return {
            'entries': entries,
            'summary': dict(stats)
        }
    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        """Execute queries on FTP log entries."""
        
        if query_type == "uploads":
            uploads = [entry for entry in log_entries if entry.get('event_type') == 'upload']
            if kwargs.get('by_user'):
                user_uploads = defaultdict(list)
                for entry in uploads:
                    if entry.get('username'):
                        user_uploads[entry['username']].append(entry)
                return dict(user_uploads)
            return uploads
        
        elif query_type == "downloads":
            downloads = [entry for entry in log_entries if entry.get('event_type') == 'download']
            if kwargs.get('by_user'):
                user_downloads = defaultdict(list)
                for entry in downloads:
                    if entry.get('username'):
                        user_downloads[entry['username']].append(entry)
                return dict(user_downloads)
            return downloads
        
        elif query_type == "login_attempts":
            return [entry for entry in log_entries if entry.get('event_type') in ['login_ok', 'login_fail']]
        
        elif query_type == "failed_logins":
            failed = [entry for entry in log_entries if entry.get('status') == 'failed']
            if kwargs.get('by_ip'):
                ip_counts = defaultdict(int)
                for entry in failed:
                    if entry.get('ip_address'):
                        ip_counts[entry['ip_address']] += 1
                return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))
            return failed
        
        elif query_type == "successful_logins":
            return [entry for entry in log_entries if entry.get('event_type') == 'login_ok']
        
        elif query_type == "bytes_transferred":
            total_up = sum(entry.get('bytes_transferred', 0) for entry in log_entries 
                          if entry.get('event_type') == 'upload')
            total_down = sum(entry.get('bytes_transferred', 0) for entry in log_entries 
                           if entry.get('event_type') == 'download')
            
            result = {
                'uploaded': total_up,
                'downloaded': total_down,
                'total': total_up + total_down
            }
            
            if kwargs.get('by_user'):
                user_stats = defaultdict(lambda: {'uploaded': 0, 'downloaded': 0})
                for entry in log_entries:
                    if entry.get('username') and entry.get('bytes_transferred'):
                        user = entry['username']
                        bytes_transferred = entry['bytes_transferred']
                        if entry.get('event_type') == 'upload':
                            user_stats[user]['uploaded'] += bytes_transferred
                        elif entry.get('event_type') == 'download':
                            user_stats[user]['downloaded'] += bytes_transferred
                
                for user in user_stats:
                    user_stats[user]['total'] = user_stats[user]['uploaded'] + user_stats[user]['downloaded']
                
                # Convert to regular dict and add to result
                user_dict = {user: stats for user, stats in user_stats.items()}
                return {**result, 'by_user': user_dict}
            
            return result
        
        elif query_type == "top_uploaders":
            limit = kwargs.get('limit', 10)
            user_bytes = defaultdict(int)
            
            for entry in log_entries:
                if entry.get('event_type') == 'upload' and entry.get('username'):
                    user_bytes[entry['username']] += entry.get('bytes_transferred', 0)
            
            return dict(sorted(user_bytes.items(), key=lambda x: x[1], reverse=True)[:limit])
        
        elif query_type == "top_downloaders":
            limit = kwargs.get('limit', 10)
            user_bytes = defaultdict(int)
            
            for entry in log_entries:
                if entry.get('event_type') == 'download' and entry.get('username'):
                    user_bytes[entry['username']] += entry.get('bytes_transferred', 0)
            
            return dict(sorted(user_bytes.items(), key=lambda x: x[1], reverse=True)[:limit])
        
        elif query_type == "file_operations":
            operations = [entry for entry in log_entries 
                         if entry.get('event_type') in ['upload', 'download', 'mkdir', 'delete']]
            
            if kwargs.get('by_type'):
                op_counts = defaultdict(int)
                for entry in operations:
                    op_counts[entry.get('event_type')] += 1
                return dict(op_counts)
            
            return operations
        
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
        """Normalize FTP log timestamp to ISO format."""
        try:
            # FTP logs typically use format like "Sat Mar 19 18:10:30 2016"
            dt = datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S %Y")
            return dt.isoformat()
        except ValueError:
            # If parsing fails, return original string
            return timestamp_str