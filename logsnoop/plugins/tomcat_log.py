"""
Tomcat Log Plugin for LogSnoop
Parses Apache Tomcat server logs including access logs and catalina logs.
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from .base import BaseLogPlugin


class TomcatLogPlugin(BaseLogPlugin):
    """Plugin for parsing Apache Tomcat server logs."""
    
    @property
    def name(self) -> str:
        return "tomcat_log"
    
    @property
    def description(self) -> str:
        return "Parse Apache Tomcat server logs (access.log, catalina.log)"
    
    @property
    def supported_queries(self) -> List[str]:
        return [
            'requests_by_status', 'requests_by_ip', 'requests_by_path', 
            'error_requests', 'slow_requests', 'bytes_served', 'top_pages',
            'top_user_agents', 'bandwidth_usage', 'response_time_stats',
            'requests_by_method', 'session_analysis', 'exception_summary',
            'daily_traffic', 'catalina_errors', 'application_errors'
        ]
    
    def __init__(self):
        super().__init__()
        # Common Tomcat access log pattern (combined format)
        self.access_pattern = re.compile(
            r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<bytes>-|\d+)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
            r'(?: (?P<response_time>\d+))?'
        )
        
        # Catalina log patterns
        self.catalina_patterns = {
            'error': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) '
                r'(?P<level>\w+) \[(?P<thread>[^\]]+)\] '
                r'(?P<class>\S+) - (?P<message>.*)'
            ),
            'exception': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) '
                r'(?P<level>SEVERE|ERROR) \[(?P<thread>[^\]]+)\] '
                r'(?P<class>\S+) - (?P<message>.*Exception.*)'
            ),
            'startup': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) '
                r'(?P<level>INFO) \[(?P<thread>[^\]]+)\] '
                r'(?P<class>\S+) - (?P<message>.*(?:Starting|Started|Stopping|Stopped).*)'
            )
        }
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        """Parse Tomcat log content."""
        lines = log_content.strip().split('\n')
        entries = []
        stats = {
            'total_requests': 0,
            'total_bytes': 0,
            'error_count': 0,
            'slow_requests': 0,
            'unique_ips': set(),
            'status_codes': {},
            'methods': {},
            'exceptions': 0,
            'applications': set()
        }
        
        log_type = self._detect_log_type(lines)
        
        for i, line in enumerate(lines):
            if not line.strip():
                continue
                
            try:
                if log_type == 'access':
                    entry = self._parse_access_log(line, i + 1)
                else:  # catalina or other tomcat logs
                    entry = self._parse_catalina_log(line, i + 1)
                
                if entry:
                    entries.append(entry)
                    self._update_stats(entry, stats)
                    
            except Exception as e:
                # Create error entry for unparseable lines
                entry = {
                    'line_number': i + 1,
                    'raw_line': line,
                    'timestamp': datetime.now().isoformat(),
                    'error': f"Parse error: {str(e)}",
                    'log_type': 'parse_error'
                }
                entries.append(entry)
        
        # Convert sets to counts for JSON serialization
        final_stats = dict(stats)
        final_stats['unique_ips'] = len(stats['unique_ips'])
        final_stats['unique_applications'] = len(stats['applications'])
        
        # Remove the set objects
        del final_stats['unique_ips']
        del final_stats['applications']
        
        # Add the counts back with proper names
        final_stats['unique_ip_count'] = len(stats['unique_ips'])
        final_stats['unique_application_count'] = len(stats['applications'])
        
        return {
            'entries': entries,
            'summary': final_stats
        }
    
    def _detect_log_type(self, lines: List[str]) -> str:
        """Detect if this is an access log or catalina log."""
        sample_lines = lines[:10]  # Check first 10 lines
        
        access_matches = 0
        catalina_matches = 0
        
        for line in sample_lines:
            if self.access_pattern.match(line):
                access_matches += 1
            elif any(pattern.match(line) for pattern in self.catalina_patterns.values()):
                catalina_matches += 1
        
        return 'access' if access_matches > catalina_matches else 'catalina'
    
    def _parse_access_log(self, line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse Tomcat access log line."""
        match = self.access_pattern.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Parse timestamp
        timestamp_str = groups['timestamp']
        try:
            # Common format: 27/Oct/2023:10:15:30 +0000
            timestamp = datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            timestamp = datetime.now()
        
        # Parse bytes
        bytes_served = 0 if groups['bytes'] == '-' else int(groups.get('bytes', 0))
        
        # Parse response time (if available)
        response_time = int(groups.get('response_time', 0)) if groups.get('response_time') else None
        
        entry = {
            'line_number': line_number,
            'raw_line': line,
            'timestamp': timestamp.isoformat(),
            'ip_address': groups['ip'],
            'method': groups['method'],
            'path': groups['path'],
            'protocol': groups['protocol'],
            'status_code': int(groups['status']),
            'bytes_served': bytes_served,
            'referer': groups.get('referer', ''),
            'user_agent': groups.get('user_agent', ''),
            'response_time': response_time,
            'log_type': 'access',
            'is_error': int(groups['status']) >= 400,
            'is_slow': response_time and response_time > 1000  # Slow if > 1 second
        }
        
        # Add fields expected by table view
        entry['source_ip'] = groups['ip']
        entry['destination_ip'] = ''  # Not available in access logs
        entry['bytes_transferred'] = bytes_served
        entry['event_type'] = 'http_request'
        entry['status'] = 'error' if int(groups['status']) >= 400 else 'completed'
        
        return entry
    
    def _parse_catalina_log(self, line: str, line_number: int) -> Optional[Dict[str, Any]]:
        """Parse Tomcat catalina log line."""
        for log_type, pattern in self.catalina_patterns.items():
            match = pattern.match(line)
            if match:
                groups = match.groupdict()
                
                # Parse timestamp
                try:
                    timestamp = datetime.strptime(groups['timestamp'], '%Y-%m-%d %H:%M:%S,%f')
                except ValueError:
                    timestamp = datetime.now()
                
                entry = {
                    'line_number': line_number,
                    'raw_line': line,
                    'timestamp': timestamp.isoformat(),
                    'log_level': groups['level'],
                    'thread': groups['thread'],
                    'class_name': groups['class'],
                    'message': groups['message'],
                    'log_type': 'catalina',
                    'catalina_type': log_type,
                    'is_error': groups['level'] in ['ERROR', 'SEVERE', 'FATAL'],
                    'is_exception': 'exception' in log_type.lower() or 'Exception' in groups['message']
                }
                
                # Add fields expected by table view
                entry['source_ip'] = ''
                entry['destination_ip'] = ''
                entry['bytes_transferred'] = 0
                entry['event_type'] = 'catalina_log'
                entry['status'] = 'error' if entry['is_error'] else 'info'
                
                return entry
        
        # If no pattern matches, create a generic entry
        return {
            'line_number': line_number,
            'raw_line': line,
            'timestamp': datetime.now().isoformat(),
            'log_type': 'catalina',
            'catalina_type': 'other',
            'message': line,
            'is_error': False,
            'is_exception': False
        }
    
    def _update_stats(self, entry: Dict[str, Any], stats: Dict[str, Any]):
        """Update statistics based on parsed entry."""
        if entry.get('log_type') == 'access':
            stats['total_requests'] += 1
            stats['total_bytes'] += entry.get('bytes_served', 0)
            
            if entry.get('ip_address'):
                stats['unique_ips'].add(entry['ip_address'])
            
            status = entry.get('status_code')
            if status:
                stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
                if status >= 400:
                    stats['error_count'] += 1
            
            method = entry.get('method')
            if method:
                stats['methods'][method] = stats['methods'].get(method, 0) + 1
            
            if entry.get('is_slow'):
                stats['slow_requests'] += 1
        
        elif entry.get('log_type') == 'catalina':
            if entry.get('is_error'):
                stats['error_count'] += 1
            
            if entry.get('is_exception'):
                stats['exceptions'] += 1
            
            # Extract application name from class if possible
            class_name = entry.get('class_name', '')
            if '.' in class_name:
                app_parts = class_name.split('.')
                if len(app_parts) > 2:
                    stats['applications'].add(app_parts[1])  # Usually the app name

    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Execute queries on parsed Tomcat log entries."""
        if query_type == 'requests_by_status':
            return self._query_requests_by_status(log_entries, **kwargs)
        elif query_type == 'requests_by_ip':
            return self._query_requests_by_ip(log_entries, **kwargs)
        elif query_type == 'requests_by_path':
            return self._query_requests_by_path(log_entries, **kwargs)
        elif query_type == 'error_requests':
            return self._query_error_requests(log_entries, **kwargs)
        elif query_type == 'slow_requests':
            return self._query_slow_requests(log_entries, **kwargs)
        elif query_type == 'bytes_served':
            return self._query_bytes_served(log_entries, **kwargs)
        elif query_type == 'top_pages':
            return self._query_top_pages(log_entries, **kwargs)
        elif query_type == 'top_user_agents':
            return self._query_top_user_agents(log_entries, **kwargs)
        elif query_type == 'bandwidth_usage':
            return self._query_bandwidth_usage(log_entries, **kwargs)
        elif query_type == 'response_time_stats':
            return self._query_response_time_stats(log_entries, **kwargs)
        elif query_type == 'requests_by_method':
            return self._query_requests_by_method(log_entries, **kwargs)
        elif query_type == 'session_analysis':
            return self._query_session_analysis(log_entries, **kwargs)
        elif query_type == 'exception_summary':
            return self._query_exception_summary(log_entries, **kwargs)
        elif query_type == 'daily_traffic':
            return self._query_daily_traffic(log_entries, **kwargs)
        elif query_type == 'catalina_errors':
            return self._query_catalina_errors(log_entries, **kwargs)
        elif query_type == 'application_errors':
            return self._query_application_errors(log_entries, **kwargs)
        else:
            return []
    
    def _query_requests_by_status(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group requests by status code."""
        access_entries = [e for e in entries if e.get('log_type') == 'access']
        status_counts = {}
        
        for entry in access_entries:
            status = entry.get('status_code')
            if status:
                if status not in status_counts:
                    status_counts[status] = {'count': 0, 'bytes': 0}
                status_counts[status]['count'] += 1
                status_counts[status]['bytes'] += entry.get('bytes_served', 0)
        
        result = []
        for status, data in sorted(status_counts.items()):
            result.append({
                'status_code': status,
                'request_count': data['count'],
                'total_bytes': data['bytes'],
                'status_description': self._get_status_description(status)
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_requests_by_ip(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group requests by IP address."""
        access_entries = [e for e in entries if e.get('log_type') == 'access']
        ip_counts = {}
        
        for entry in access_entries:
            ip = entry.get('ip_address')
            if ip:
                if ip not in ip_counts:
                    ip_counts[ip] = {'count': 0, 'bytes': 0, 'errors': 0}
                ip_counts[ip]['count'] += 1
                ip_counts[ip]['bytes'] += entry.get('bytes_served', 0)
                if entry.get('is_error'):
                    ip_counts[ip]['errors'] += 1
        
        result = []
        for ip, data in sorted(ip_counts.items(), key=lambda x: x[1]['count'], reverse=True):
            result.append({
                'ip_address': ip,
                'request_count': data['count'],
                'total_bytes': data['bytes'],
                'error_count': data['errors'],
                'error_rate': round(data['errors'] / data['count'] * 100, 2) if data['count'] > 0 else 0
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_requests_by_path(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group requests by path."""
        access_entries = [e for e in entries if e.get('log_type') == 'access']
        path_counts = {}
        
        for entry in access_entries:
            path = entry.get('path')
            if path:
                if path not in path_counts:
                    path_counts[path] = {'count': 0, 'bytes': 0, 'avg_response_time': 0, 'response_times': []}
                path_counts[path]['count'] += 1
                path_counts[path]['bytes'] += entry.get('bytes_served', 0)
                if entry.get('response_time'):
                    path_counts[path]['response_times'].append(entry['response_time'])
        
        result = []
        for path, data in sorted(path_counts.items(), key=lambda x: x[1]['count'], reverse=True):
            avg_time = sum(data['response_times']) / len(data['response_times']) if data['response_times'] else 0
            result.append({
                'path': path,
                'request_count': data['count'],
                'total_bytes': data['bytes'],
                'avg_response_time': round(avg_time, 2)
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_error_requests(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Get error requests (4xx and 5xx status codes)."""
        access_entries = [e for e in entries if e.get('log_type') == 'access' and e.get('is_error')]
        
        limit = kwargs.get('limit')
        return access_entries[:limit] if limit else access_entries
    
    def _query_slow_requests(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Get slow requests (response time > threshold)."""
        threshold = kwargs.get('threshold', 1000)  # Default 1 second
        slow_entries = [
            e for e in entries 
            if e.get('log_type') == 'access' and 
               e.get('response_time') and 
               e.get('response_time') > threshold
        ]
        
        # Sort by response time descending
        slow_entries.sort(key=lambda x: x.get('response_time', 0), reverse=True)
        
        limit = kwargs.get('limit')
        return slow_entries[:limit] if limit else slow_entries
    
    def _query_exception_summary(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Summarize exceptions from catalina logs."""
        exception_entries = [e for e in entries if e.get('is_exception')]
        exception_counts = {}
        
        for entry in exception_entries:
            message = entry.get('message', '')
            # Extract exception type
            exception_type = 'Unknown'
            if 'Exception' in message:
                words = message.split()
                for word in words:
                    if 'Exception' in word:
                        exception_type = word.split('.')[-1]  # Get class name without package
                        break
            
            if exception_type not in exception_counts:
                exception_counts[exception_type] = {
                    'count': 0,
                    'latest_timestamp': entry.get('timestamp'),
                    'sample_message': message[:200]  # First 200 chars
                }
            
            exception_counts[exception_type]['count'] += 1
            # Keep the latest timestamp
            if entry.get('timestamp') > exception_counts[exception_type]['latest_timestamp']:
                exception_counts[exception_type]['latest_timestamp'] = entry.get('timestamp')
        
        result = []
        for exc_type, data in sorted(exception_counts.items(), key=lambda x: x[1]['count'], reverse=True):
            result.append({
                'exception_type': exc_type,
                'count': data['count'],
                'latest_occurrence': data['latest_timestamp'],
                'sample_message': data['sample_message']
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_catalina_errors(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Get catalina error log entries."""
        error_entries = [
            e for e in entries 
            if e.get('log_type') == 'catalina' and e.get('is_error')
        ]
        
        limit = kwargs.get('limit')
        return error_entries[:limit] if limit else error_entries
    
    def _get_status_description(self, status_code: int) -> str:
        """Get HTTP status code description."""
        status_descriptions = {
            200: 'OK', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
            400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
            405: 'Method Not Allowed', 500: 'Internal Server Error', 502: 'Bad Gateway',
            503: 'Service Unavailable', 504: 'Gateway Timeout'
        }
        return status_descriptions.get(status_code, 'Unknown')
    
    # Additional query methods would be implemented similarly...
    def _query_bytes_served(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Calculate bytes served statistics."""
        access_entries = [e for e in entries if e.get('log_type') == 'access']
        total_bytes = sum(e.get('bytes_served', 0) for e in access_entries)
        
        return [{
            'total_bytes_served': total_bytes,
            'average_per_request': round(total_bytes / len(access_entries), 2) if access_entries else 0,
            'total_requests': len(access_entries)
        }]
    
    def _query_top_pages(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Get top requested pages."""
        return self._query_requests_by_path(entries, **kwargs)
    
    def _query_top_user_agents(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Get top user agents."""
        access_entries = [e for e in entries if e.get('log_type') == 'access']
        ua_counts = {}
        
        for entry in access_entries:
            ua = entry.get('user_agent', 'Unknown')
            ua_counts[ua] = ua_counts.get(ua, 0) + 1
        
        result = []
        for ua, count in sorted(ua_counts.items(), key=lambda x: x[1], reverse=True):
            result.append({
                'user_agent': ua,
                'request_count': count
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_bandwidth_usage(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Calculate bandwidth usage statistics."""
        return self._query_bytes_served(entries, **kwargs)
    
    def _query_response_time_stats(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Calculate response time statistics."""
        timed_entries = [e for e in entries if e.get('response_time')]
        
        if not timed_entries:
            return [{'message': 'No response time data available'}]
        
        times = [e['response_time'] for e in timed_entries]
        times.sort()
        
        return [{
            'total_requests_with_timing': len(times),
            'min_response_time': min(times),
            'max_response_time': max(times),
            'avg_response_time': round(sum(times) / len(times), 2),
            'median_response_time': times[len(times) // 2],
            'p95_response_time': times[int(len(times) * 0.95)] if len(times) > 20 else max(times)
        }]
    
    def _query_requests_by_method(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group requests by HTTP method."""
        access_entries = [e for e in entries if e.get('log_type') == 'access']
        method_counts = {}
        
        for entry in access_entries:
            method = entry.get('method', 'Unknown')
            method_counts[method] = method_counts.get(method, 0) + 1
        
        result = []
        for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
            result.append({
                'http_method': method,
                'request_count': count
            })
        
        return result
    
    def _query_session_analysis(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Analyze session-related patterns."""
        access_entries = [e for e in entries if e.get('log_type') == 'access']
        
        # Look for JSESSIONID in paths
        session_requests = [e for e in access_entries if 'jsessionid' in e.get('path', '').lower()]
        
        return [{
            'total_requests': len(access_entries),
            'session_requests': len(session_requests),
            'session_percentage': round(len(session_requests) / len(access_entries) * 100, 2) if access_entries else 0
        }]
    
    def _query_daily_traffic(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group traffic by day."""
        access_entries = [e for e in entries if e.get('log_type') == 'access']
        daily_stats = {}
        
        for entry in access_entries:
            try:
                date = datetime.fromisoformat(entry['timestamp'].replace('Z', '')).date()
                date_str = date.isoformat()
                
                if date_str not in daily_stats:
                    daily_stats[date_str] = {'requests': 0, 'bytes': 0, 'errors': 0}
                
                daily_stats[date_str]['requests'] += 1
                daily_stats[date_str]['bytes'] += entry.get('bytes_served', 0)
                if entry.get('is_error'):
                    daily_stats[date_str]['errors'] += 1
            except:
                continue
        
        result = []
        for date_str, stats in sorted(daily_stats.items()):
            result.append({
                'date': date_str,
                'requests': stats['requests'],
                'bytes_served': stats['bytes'],
                'error_count': stats['errors'],
                'error_rate': round(stats['errors'] / stats['requests'] * 100, 2) if stats['requests'] > 0 else 0
            })
        
        return result
    
    def _query_application_errors(self, entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group errors by application."""
        catalina_entries = [e for e in entries if e.get('log_type') == 'catalina' and e.get('is_error')]
        app_errors = {}
        
        for entry in catalina_entries:
            class_name = entry.get('class_name', 'Unknown')
            # Extract app name from class name
            app_name = 'Unknown'
            if '.' in class_name:
                parts = class_name.split('.')
                if len(parts) > 2:
                    app_name = parts[1]  # Usually the application name
            
            if app_name not in app_errors:
                app_errors[app_name] = {'count': 0, 'latest_error': entry.get('timestamp')}
            
            app_errors[app_name]['count'] += 1
            if entry.get('timestamp') > app_errors[app_name]['latest_error']:
                app_errors[app_name]['latest_error'] = entry.get('timestamp')
        
        result = []
        for app_name, data in sorted(app_errors.items(), key=lambda x: x[1]['count'], reverse=True):
            result.append({
                'application': app_name,
                'error_count': data['count'],
                'latest_error': data['latest_error']
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result