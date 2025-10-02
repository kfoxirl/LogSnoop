"""
HTTP Access Log Plugin
Parses HTTP web server access logs (Apache, Nginx)
"""

import re
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict
from urllib.parse import urlparse, parse_qs
from .base import BaseLogPlugin


class HTTPAccessPlugin(BaseLogPlugin):
    """Plugin for parsing HTTP access logs."""
    
    @property
    def name(self) -> str:
        return "http_access"
    
    @property
    def description(self) -> str:
        return "Parser for HTTP access logs (Apache, Nginx)"
    
    @property
    def supported_queries(self) -> List[str]:
        return [
            "requests_by_status",
            "requests_by_ip",
            "requests_by_path",
            "error_requests",
            "bytes_served",
            "top_pages",
            "top_referrers",
            "top_user_agents",
            "bandwidth_usage",
            "response_time_stats"
        ]
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        """Parse HTTP access log content."""
        lines = log_content.strip().split('\n')
        entries = []
        stats = defaultdict(lambda: 0)
        total_bytes = 0
        response_times = []
        
        # Common Log Format pattern
        # IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
        log_pattern = r'([0-9.]+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]*)"?\s+([0-9]+)\s+([0-9-]+)(?:\s+"([^"]*)")?\s*(?:"([^"]*)")?\s*(?:([0-9]+))?'
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
                
            entry = {
                'line_number': line_num,
                'raw_line': line,
                'ip_address': None,
                'timestamp': None,
                'method': None,
                'path': None,
                'protocol': None,
                'status_code': None,
                'bytes_sent': 0,
                'referer': None,
                'user_agent': None,
                'response_time': None,
                'event_type': 'http_request'
            }
            
            match = re.search(log_pattern, line)
            if match:
                entry['ip_address'] = match.group(1)
                entry['timestamp'] = self.normalize_timestamp(match.group(2))
                
                # Parse request line (method path protocol)
                request_line = match.group(3)
                if request_line and request_line != '-':
                    request_parts = request_line.split()
                    if len(request_parts) >= 2:
                        entry['method'] = request_parts[0]
                        entry['path'] = request_parts[1]
                        if len(request_parts) >= 3:
                            entry['protocol'] = request_parts[2]
                
                entry['status_code'] = int(match.group(4))
                
                # Parse bytes sent
                bytes_str = match.group(5)
                if bytes_str and bytes_str != '-':
                    entry['bytes_sent'] = int(bytes_str)
                    total_bytes += entry['bytes_sent']
                
                # Parse referer
                if match.group(6) and match.group(6) != '-':
                    entry['referer'] = match.group(6)
                
                # Parse user agent
                if match.group(7):
                    entry['user_agent'] = match.group(7)
                
                # Parse response time (if available)
                if match.group(8):
                    entry['response_time'] = int(match.group(8))
                    response_times.append(entry['response_time'])
                
                # Update statistics
                stats[f'status_{entry["status_code"]}'] += 1
                if entry['method']:
                    stats[f'method_{entry["method"]}'] += 1
                
                # Categorize status codes
                status = entry['status_code']
                if 200 <= status < 300:
                    stats['success_requests'] += 1
                elif 300 <= status < 400:
                    stats['redirect_requests'] += 1
                elif 400 <= status < 500:
                    stats['client_error_requests'] += 1
                elif status >= 500:
                    stats['server_error_requests'] += 1
            
            if self.validate_entry(entry):
                entries.append(entry)
        
        # Calculate additional statistics
        unique_ips = set(entry.get('ip_address') for entry in entries if entry.get('ip_address'))
        unique_paths = set(entry.get('path') for entry in entries if entry.get('path'))
        
        additional_stats = {
            'total_entries': len(entries),
            'unique_ips': len(unique_ips),
            'unique_paths': len(unique_paths),
            'total_bytes_served': total_bytes,
            'avg_response_time': sum(response_times) / len(response_times) if response_times else 0,
            'min_response_time': min(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0
        }
        
        # Merge stats
        final_stats = dict(stats)
        final_stats.update(additional_stats)
        
        return {
            'entries': entries,
            'summary': final_stats
        }
    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        """Execute queries on HTTP access log entries."""
        
        if query_type == "requests_by_status":
            status_counts = defaultdict(int)
            for entry in log_entries:
                if entry.get('status_code'):
                    status_counts[entry['status_code']] += 1
            return dict(sorted(status_counts.items()))
        
        elif query_type == "requests_by_ip":
            ip = kwargs.get('ip_address')
            if ip:
                return [entry for entry in log_entries if entry.get('ip_address') == ip]
            else:
                ip_counts = defaultdict(int)
                for entry in log_entries:
                    if entry.get('ip_address'):
                        ip_counts[entry['ip_address']] += 1
                return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "requests_by_path":
            path = kwargs.get('path')
            if path:
                return [entry for entry in log_entries if entry.get('path') == path]
            else:
                path_counts = defaultdict(int)
                for entry in log_entries:
                    if entry.get('path'):
                        path_counts[entry['path']] += 1
                return dict(sorted(path_counts.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "error_requests":
            min_status = kwargs.get('min_status', 400)
            errors = [entry for entry in log_entries 
                     if entry.get('status_code') and entry['status_code'] >= min_status]
            
            if kwargs.get('by_status'):
                status_counts = defaultdict(int)
                for entry in errors:
                    status_counts[entry['status_code']] += 1
                return dict(sorted(status_counts.items()))
            
            return errors
        
        elif query_type == "bytes_served":
            total_bytes = sum(entry.get('bytes_sent', 0) for entry in log_entries)
            
            result = {'total': total_bytes}
            
            if kwargs.get('by_ip'):
                ip_bytes = defaultdict(int)
                for entry in log_entries:
                    if entry.get('ip_address'):
                        ip_bytes[entry['ip_address']] += entry.get('bytes_sent', 0)
                by_ip_dict = dict(sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True))
                return {**result, 'by_ip': by_ip_dict}
            
            if kwargs.get('by_path'):
                path_bytes = defaultdict(int)
                for entry in log_entries:
                    if entry.get('path'):
                        path_bytes[entry['path']] += entry.get('bytes_sent', 0)
                by_path_dict = dict(sorted(path_bytes.items(), key=lambda x: x[1], reverse=True)) 
                return {**result, 'by_path': by_path_dict}
            
            return result
        
        elif query_type == "top_pages":
            limit = kwargs.get('limit', 10)
            path_counts = defaultdict(int)
            
            for entry in log_entries:
                if entry.get('path') and entry.get('status_code') and entry['status_code'] < 400:
                    path_counts[entry['path']] += 1
            
            return dict(sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:limit])
        
        elif query_type == "top_referrers":
            limit = kwargs.get('limit', 10)
            referer_counts = defaultdict(int)
            
            for entry in log_entries:
                referer = entry.get('referer')
                if referer and referer != '-':
                    referer_counts[referer] += 1
            
            return dict(sorted(referer_counts.items(), key=lambda x: x[1], reverse=True)[:limit])
        
        elif query_type == "top_user_agents":
            limit = kwargs.get('limit', 10)
            ua_counts = defaultdict(int)
            
            for entry in log_entries:
                user_agent = entry.get('user_agent')
                if user_agent:
                    ua_counts[user_agent] += 1
            
            return dict(sorted(ua_counts.items(), key=lambda x: x[1], reverse=True)[:limit])
        
        elif query_type == "bandwidth_usage":
            # Group by time period (hour, day, etc.)
            period = kwargs.get('period', 'hour')  # hour, day, month
            bandwidth_by_period = defaultdict(int)
            
            for entry in log_entries:
                timestamp = entry.get('timestamp')
                bytes_sent = entry.get('bytes_sent', 0)
                
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        
                        if period == 'hour':
                            key = dt.strftime('%Y-%m-%d %H:00')
                        elif period == 'day':
                            key = dt.strftime('%Y-%m-%d')
                        elif period == 'month':
                            key = dt.strftime('%Y-%m')
                        else:
                            key = timestamp
                        
                        bandwidth_by_period[key] += bytes_sent
                    except:
                        continue
            
            return dict(sorted(bandwidth_by_period.items()))
        
        elif query_type == "response_time_stats":
            response_times = [entry.get('response_time') for entry in log_entries 
                            if entry.get('response_time') is not None and isinstance(entry.get('response_time'), (int, float))]
            
            if not response_times:
                return {'count': 0, 'avg': 0, 'min': 0, 'max': 0}
            
            return {
                'count': len(response_times),
                'avg': sum(response_times) / len(response_times),
                'min': min(response_times),
                'max': max(response_times),
                'slow_requests': len([rt for rt in response_times if rt > kwargs.get('slow_threshold', 1000)])
            }
        
        else:
            raise ValueError(f"Unsupported query type: {query_type}")
    
    def normalize_timestamp(self, timestamp_str: str) -> str:
        """Normalize HTTP log timestamp to ISO format."""
        try:
            # Apache format: "10/Oct/2000:13:55:36 -0700"
            dt = datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            return dt.isoformat()
        except ValueError:
            try:
                # Try alternative format: "2000-10-10 13:55:36"
                dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                return dt.isoformat()
            except ValueError:
                # If parsing fails, return original string
                return timestamp_str