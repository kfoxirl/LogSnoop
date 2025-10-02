"""
IIS Log Plugin for LogSnoop
Parses Microsoft Internet Information Services (IIS) server logs.
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from .base import BaseLogPlugin


class IISLogPlugin(BaseLogPlugin):
    """Plugin for parsing Microsoft IIS server logs."""
    
    @property
    def name(self) -> str:
        return "iis_log"
    
    @property
    def description(self) -> str:
        return "Parse Microsoft IIS server logs (W3C Extended format)"
    
    @property
    def supported_queries(self) -> List[str]:
        return [
            'requests_by_status', 'requests_by_ip', 'requests_by_path', 
            'error_requests', 'slow_requests', 'bytes_served', 'top_pages',
            'top_user_agents', 'bandwidth_usage', 'response_time_stats',
            'requests_by_method', 'requests_by_site', 'win32_status_analysis',
            'daily_traffic', 'client_errors', 'server_errors', 'asp_net_errors',
            'top_referrers', 'query_string_analysis', 'protocol_analysis'
        ]
    
    def __init__(self):
        super().__init__()
        # IIS W3C Extended Log Format fields mapping
        self.field_mappings = {
            'date': 'date',
            'time': 'time', 
            's-sitename': 'site_name',
            's-computername': 'computer_name',
            's-ip': 'server_ip',
            'cs-method': 'method',
            'cs-uri-stem': 'uri_stem',
            'cs-uri-query': 'uri_query',
            's-port': 'server_port',
            'cs-username': 'username',
            'c-ip': 'client_ip',
            'cs(User-Agent)': 'user_agent',
            'cs(Cookie)': 'cookie',
            'cs(Referer)': 'referer',
            'cs-host': 'host',
            'sc-status': 'status_code',
            'sc-substatus': 'substatus',
            'sc-win32-status': 'win32_status',
            'sc-bytes': 'bytes_sent',
            'cs-bytes': 'bytes_received',
            'time-taken': 'time_taken',
            'cs-version': 'http_version'
        }
        
        # Common field order in IIS logs
        self.default_fields = [
            'date', 'time', 'c-ip', 'cs-username', 's-sitename', 's-computername',
            's-ip', 's-port', 'cs-method', 'cs-uri-stem', 'cs-uri-query',
            'sc-status', 'sc-win32-status', 'sc-bytes', 'cs-bytes', 'time-taken',
            'cs-version', 'cs(User-Agent)', 'cs(Cookie)', 'cs(Referer)'
        ]
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        """Parse IIS log content."""
        lines = log_content.strip().split('\n')
        entries = []
        stats = {
            'total_requests': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'error_count': 0,
            'slow_requests': 0,
            'unique_ips': set(),
            'status_codes': {},
            'methods': {},
            'sites': set(),
            'win32_errors': {},
            'asp_net_errors': 0
        }
        
        fields = []
        
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            
            # Skip comment lines but extract field definitions
            if line.startswith('#'):
                if line.startswith('#Fields:'):
                    fields = line[9:].strip().split()
                continue
            
            try:
                entry = self._parse_log_line(line, fields, i + 1)
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
        
        # Remove the set objects and add counts
        del final_stats['unique_ips']
        del final_stats['sites']
        
        final_stats['unique_ip_count'] = len(stats['unique_ips'])
        final_stats['unique_site_count'] = len(stats['sites'])
        
        return {
            'entries': entries,
            'summary': final_stats
        }
    
    def _parse_log_line(self, line: str, fields: List[str], line_number: int) -> Optional[Dict[str, Any]]:
        """Parse individual IIS log line."""
        # Split by spaces, handling quoted strings
        parts = self._split_log_line(line)
        
        # Use default fields if none specified
        if not fields:
            fields = self.default_fields
        
        # Ensure we have enough parts for the fields
        while len(parts) < len(fields):
            parts.append('-')
        
        # Create entry dictionary
        entry = {
            'line_number': line_number,
            'raw_line': line,
            'log_type': 'iis_access'
        }
        
        # Map fields to values
        for i, field in enumerate(fields):
            if i < len(parts):
                mapped_field = self.field_mappings.get(field, field.replace('-', '_').replace('(', '_').replace(')', ''))
                value = parts[i] if parts[i] != '-' else None
                entry[mapped_field] = value
        
        # Process special fields
        self._process_entry_fields(entry)
        
        return entry
    
    def _split_log_line(self, line: str) -> List[str]:
        """Split log line handling quoted strings properly."""
        parts = []
        current_part = ""
        in_quotes = False
        
        i = 0
        while i < len(line):
            char = line[i]
            
            if char == '"':
                in_quotes = not in_quotes
                current_part += char
            elif char == ' ' and not in_quotes:
                if current_part:
                    parts.append(current_part)
                    current_part = ""
            else:
                current_part += char
            
            i += 1
        
        if current_part:
            parts.append(current_part)
        
        return parts
    
    def _process_entry_fields(self, entry: Dict[str, Any]):
        """Process and normalize entry fields."""
        # Combine date and time into timestamp
        date_str = entry.get('date')
        time_str = entry.get('time')
        
        if date_str and time_str:
            try:
                timestamp = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                entry['timestamp'] = timestamp.isoformat()
            except ValueError:
                entry['timestamp'] = datetime.now().isoformat()
        else:
            entry['timestamp'] = datetime.now().isoformat()
        
        # Convert numeric fields
        numeric_fields = {
            'status_code': 'sc_status',
            'substatus': 'substatus', 
            'win32_status': 'win32_status',
            'bytes_sent': 'bytes_sent',
            'bytes_received': 'bytes_received',
            'time_taken': 'time_taken',
            'server_port': 'server_port'
        }
        
        for field_name, entry_key in numeric_fields.items():
            if entry.get(entry_key):
                try:
                    entry[entry_key] = int(entry[entry_key])
                except (ValueError, TypeError):
                    entry[entry_key] = 0
        
        # Build full URL
        uri_stem = entry.get('uri_stem', '')
        uri_query = entry.get('uri_query', '')
        if uri_query and uri_query != '-':
            entry['full_url'] = f"{uri_stem}?{uri_query}"
        else:
            entry['full_url'] = uri_stem
        
        # Determine if error
        status_code = entry.get('status_code', 0)
        entry['is_error'] = status_code >= 400
        entry['is_client_error'] = 400 <= status_code < 500
        entry['is_server_error'] = status_code >= 500
        
        # Check for slow requests (>2 seconds by default)
        time_taken = entry.get('time_taken', 0)
        entry['is_slow'] = time_taken > 2000  # IIS time_taken is in milliseconds
        
        # Check for ASP.NET errors (common substatus codes)
        substatus = entry.get('substatus', 0)
        entry['is_asp_net_error'] = status_code == 500 and substatus in [0, 19, 21, 22, 23]
        
        # Clean up quoted strings
        string_fields = ['user_agent', 'referer', 'cookie', 'host']
        for field in string_fields:
            if entry.get(field) and isinstance(entry[field], str):
                entry[field] = entry[field].strip('"')
        
        # Add fields expected by table view
        entry['source_ip'] = entry.get('client_ip', '')
        entry['destination_ip'] = entry.get('server_ip', '')
        entry['bytes_transferred'] = entry.get('bytes_sent', 0)
        entry['event_type'] = 'http_request'
        entry['status'] = 'completed' if not entry.get('is_error') else 'error'
    
    def _update_stats(self, entry: Dict[str, Any], stats: Dict[str, Any]):
        """Update statistics based on parsed entry."""
        if entry.get('log_type') != 'iis_access':
            return  # Only process IIS access entries for stats
            
        stats['total_requests'] += 1
        stats['total_bytes_sent'] += entry.get('bytes_sent', 0)
        stats['total_bytes_received'] += entry.get('bytes_received', 0)
        
        if entry.get('client_ip'):
            stats['unique_ips'].add(entry['client_ip'])
        
        if entry.get('site_name'):
            stats['sites'].add(entry['site_name'])
        
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
        
        win32_status = entry.get('win32_status')
        if win32_status and win32_status != 0:
            stats['win32_errors'][win32_status] = stats['win32_errors'].get(win32_status, 0) + 1
        
        if entry.get('is_asp_net_error'):
            stats['asp_net_errors'] += 1
    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Execute queries on parsed IIS log entries."""
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
        elif query_type == 'requests_by_site':
            return self._query_requests_by_site(log_entries, **kwargs)
        elif query_type == 'win32_status_analysis':
            return self._query_win32_status_analysis(log_entries, **kwargs)
        elif query_type == 'daily_traffic':
            return self._query_daily_traffic(log_entries, **kwargs)
        elif query_type == 'client_errors':
            return self._query_client_errors(log_entries, **kwargs)
        elif query_type == 'server_errors':
            return self._query_server_errors(log_entries, **kwargs)
        elif query_type == 'asp_net_errors':
            return self._query_asp_net_errors(log_entries, **kwargs)
        elif query_type == 'top_referrers':
            return self._query_top_referrers(log_entries, **kwargs)
        elif query_type == 'query_string_analysis':
            return self._query_query_string_analysis(log_entries, **kwargs)
        elif query_type == 'protocol_analysis':
            return self._query_protocol_analysis(log_entries, **kwargs)
        else:
            return []
    
    def _query_requests_by_status(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group requests by status code."""
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        status_counts = {}
        
        for entry in iis_entries:
            status = entry.get('status_code')
            substatus = entry.get('substatus', 0)
            status_key = f"{status}.{substatus}" if substatus else str(status)
            
            if status:
                if status_key not in status_counts:
                    status_counts[status_key] = {
                        'count': 0, 'bytes_sent': 0, 'bytes_received': 0,
                        'avg_time': 0, 'times': []
                    }
                status_counts[status_key]['count'] += 1
                status_counts[status_key]['bytes_sent'] += entry.get('bytes_sent', 0)
                status_counts[status_key]['bytes_received'] += entry.get('bytes_received', 0)
                if entry.get('time_taken'):
                    status_counts[status_key]['times'].append(entry['time_taken'])
        
        result = []
        for status_key, data in sorted(status_counts.items()):
            avg_time = sum(data['times']) / len(data['times']) if data['times'] else 0
            status_parts = status_key.split('.')
            main_status = int(status_parts[0])
            
            result.append({
                'status_code': status_key,
                'request_count': data['count'],
                'bytes_sent': data['bytes_sent'],
                'bytes_received': data['bytes_received'],
                'avg_response_time': round(avg_time, 2),
                'status_description': self._get_iis_status_description(main_status)
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_requests_by_site(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group requests by IIS site."""
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        site_counts = {}
        
        for entry in iis_entries:
            site = entry.get('site_name', 'Default')
            if site not in site_counts:
                site_counts[site] = {
                    'count': 0, 'bytes_sent': 0, 'bytes_received': 0, 'errors': 0
                }
            site_counts[site]['count'] += 1
            site_counts[site]['bytes_sent'] += entry.get('bytes_sent', 0)
            site_counts[site]['bytes_received'] += entry.get('bytes_received', 0)
            if entry.get('is_error'):
                site_counts[site]['errors'] += 1
        
        result = []
        for site, data in sorted(site_counts.items(), key=lambda x: x[1]['count'], reverse=True):
            result.append({
                'site_name': site,
                'request_count': data['count'],
                'bytes_sent': data['bytes_sent'],
                'bytes_received': data['bytes_received'],
                'error_count': data['errors'],
                'error_rate': round(data['errors'] / data['count'] * 100, 2) if data['count'] > 0 else 0
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_win32_status_analysis(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Analyze Win32 status codes."""
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        win32_counts = {}
        
        for entry in iis_entries:
            win32_status = entry.get('win32_status')
            if win32_status and win32_status != 0:
                if win32_status not in win32_counts:
                    win32_counts[win32_status] = {
                        'count': 0,
                        'sample_url': entry.get('full_url', ''),
                        'latest_timestamp': entry.get('timestamp')
                    }
                win32_counts[win32_status]['count'] += 1
                if entry.get('timestamp') > win32_counts[win32_status]['latest_timestamp']:
                    win32_counts[win32_status]['latest_timestamp'] = entry.get('timestamp')
        
        result = []
        for win32_code, data in sorted(win32_counts.items(), key=lambda x: x[1]['count'], reverse=True):
            result.append({
                'win32_status': win32_code,
                'count': data['count'],
                'description': self._get_win32_description(win32_code),
                'sample_url': data['sample_url'],
                'latest_occurrence': data['latest_timestamp']
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_asp_net_errors(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Get ASP.NET specific errors."""
        asp_net_entries = [e for e in log_entries if e.get('is_asp_net_error')]
        
        limit = kwargs.get('limit')
        return asp_net_entries[:limit] if limit else asp_net_entries
    
    def _query_client_errors(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Get client errors (4xx status codes)."""
        client_error_entries = [e for e in log_entries if e.get('is_client_error')]
        
        limit = kwargs.get('limit')
        return client_error_entries[:limit] if limit else client_error_entries
    
    def _query_server_errors(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Get server errors (5xx status codes)."""
        server_error_entries = [e for e in log_entries if e.get('is_server_error')]
        
        limit = kwargs.get('limit')
        return server_error_entries[:limit] if limit else server_error_entries
    
    def _get_iis_status_description(self, status_code: int) -> str:
        """Get IIS/HTTP status code description."""
        status_descriptions = {
            200: 'OK', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
            400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
            405: 'Method Not Allowed', 500: 'Internal Server Error', 502: 'Bad Gateway',
            503: 'Service Unavailable', 504: 'Gateway Timeout'
        }
        return status_descriptions.get(status_code, 'Unknown')
    
    def _get_win32_description(self, win32_code: int) -> str:
        """Get Win32 error code description."""
        win32_descriptions = {
            0: 'Success',
            2: 'File not found',
            3: 'Path not found', 
            5: 'Access denied',
            32: 'File in use',
            64: 'Network name not found',
            1229: 'Connection aborted by client',
            1236: 'Connection aborted by local system'
        }
        return win32_descriptions.get(win32_code, f'Win32 Error {win32_code}')
    
    # Implement remaining query methods using similar patterns...
    def _query_requests_by_ip(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group requests by IP address."""
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        ip_counts = {}
        
        for entry in iis_entries:
            ip = entry.get('client_ip')
            if ip:
                if ip not in ip_counts:
                    ip_counts[ip] = {'count': 0, 'bytes_sent': 0, 'errors': 0}
                ip_counts[ip]['count'] += 1
                ip_counts[ip]['bytes_sent'] += entry.get('bytes_sent', 0)
                if entry.get('is_error'):
                    ip_counts[ip]['errors'] += 1
        
        result = []
        for ip, data in sorted(ip_counts.items(), key=lambda x: x[1]['count'], reverse=True):
            result.append({
                'client_ip': ip,
                'request_count': data['count'],
                'bytes_sent': data['bytes_sent'],
                'error_count': data['errors'],
                'error_rate': round(data['errors'] / data['count'] * 100, 2) if data['count'] > 0 else 0
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_requests_by_path(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        """Group requests by path."""
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        path_counts = {}
        
        for entry in iis_entries:
            path = entry.get('uri_stem')
            if path:
                if path not in path_counts:
                    path_counts[path] = {'count': 0, 'bytes_sent': 0, 'avg_time': 0, 'times': []}
                path_counts[path]['count'] += 1
                path_counts[path]['bytes_sent'] += entry.get('bytes_sent', 0)
                if entry.get('time_taken'):
                    path_counts[path]['times'].append(entry['time_taken'])
        
        result = []
        for path, data in sorted(path_counts.items(), key=lambda x: x[1]['count'], reverse=True):
            avg_time = sum(data['times']) / len(data['times']) if data['times'] else 0
            result.append({
                'uri_stem': path,
                'request_count': data['count'],
                'bytes_sent': data['bytes_sent'],
                'avg_response_time': round(avg_time, 2)
            })
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    # Additional simplified implementations for remaining methods
    def _query_error_requests(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        error_entries = [e for e in log_entries if e.get('is_error')]
        limit = kwargs.get('limit')
        return error_entries[:limit] if limit else error_entries
    
    def _query_slow_requests(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        slow_entries = [e for e in log_entries if e.get('is_slow')]
        slow_entries.sort(key=lambda x: x.get('time_taken', 0), reverse=True)
        limit = kwargs.get('limit')
        return slow_entries[:limit] if limit else slow_entries
    
    def _query_bytes_served(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        total_sent = sum(e.get('bytes_sent', 0) for e in iis_entries)
        total_received = sum(e.get('bytes_received', 0) for e in iis_entries)
        
        return [{
            'total_bytes_sent': total_sent,
            'total_bytes_received': total_received,
            'total_requests': len(iis_entries)
        }]
    
    def _query_top_pages(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        return self._query_requests_by_path(log_entries, **kwargs)
    
    def _query_top_user_agents(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        ua_counts = {}
        
        for entry in iis_entries:
            ua = entry.get('user_agent', 'Unknown')
            ua_counts[ua] = ua_counts.get(ua, 0) + 1
        
        result = []
        for ua, count in sorted(ua_counts.items(), key=lambda x: x[1], reverse=True):
            result.append({'user_agent': ua, 'request_count': count})
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_bandwidth_usage(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        return self._query_bytes_served(log_entries, **kwargs)
    
    def _query_response_time_stats(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        timed_entries = [e for e in log_entries if e.get('time_taken')]
        
        if not timed_entries:
            return [{'message': 'No response time data available'}]
        
        times = [e['time_taken'] for e in timed_entries]
        times.sort()
        
        return [{
            'total_requests_with_timing': len(times),
            'min_response_time_ms': min(times),
            'max_response_time_ms': max(times),
            'avg_response_time_ms': round(sum(times) / len(times), 2),
            'median_response_time_ms': times[len(times) // 2],
            'p95_response_time_ms': times[int(len(times) * 0.95)] if len(times) > 20 else max(times)
        }]
    
    def _query_requests_by_method(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        method_counts = {}
        
        for entry in iis_entries:
            method = entry.get('method', 'Unknown')
            method_counts[method] = method_counts.get(method, 0) + 1
        
        result = []
        for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
            result.append({'http_method': method, 'request_count': count})
        
        return result
    
    def _query_daily_traffic(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        daily_stats = {}
        
        for entry in iis_entries:
            try:
                date = datetime.fromisoformat(entry['timestamp'].replace('Z', '')).date()
                date_str = date.isoformat()
                
                if date_str not in daily_stats:
                    daily_stats[date_str] = {'requests': 0, 'bytes_sent': 0, 'errors': 0}
                
                daily_stats[date_str]['requests'] += 1
                daily_stats[date_str]['bytes_sent'] += entry.get('bytes_sent', 0)
                if entry.get('is_error'):
                    daily_stats[date_str]['errors'] += 1
            except:
                continue
        
        result = []
        for date_str, stats in sorted(daily_stats.items()):
            result.append({
                'date': date_str,
                'requests': stats['requests'],
                'bytes_sent': stats['bytes_sent'],
                'error_count': stats['errors'],
                'error_rate': round(stats['errors'] / stats['requests'] * 100, 2) if stats['requests'] > 0 else 0
            })
        
        return result
    
    def _query_top_referrers(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        referrer_counts = {}
        
        for entry in iis_entries:
            referrer = entry.get('referer')
            if referrer and referrer != '-':
                referrer_counts[referrer] = referrer_counts.get(referrer, 0) + 1
        
        result = []
        for referrer, count in sorted(referrer_counts.items(), key=lambda x: x[1], reverse=True):
            result.append({'referer': referrer, 'request_count': count})
        
        limit = kwargs.get('limit')
        return result[:limit] if limit else result
    
    def _query_query_string_analysis(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        
        with_query = len([e for e in iis_entries if e.get('uri_query') and e.get('uri_query') != '-'])
        without_query = len(iis_entries) - with_query
        
        return [{
            'total_requests': len(iis_entries),
            'requests_with_query_string': with_query,
            'requests_without_query_string': without_query,
            'query_string_percentage': round(with_query / len(iis_entries) * 100, 2) if iis_entries else 0
        }]
    
    def _query_protocol_analysis(self, log_entries: List[Dict[str, Any]], **kwargs) -> List[Dict[str, Any]]:
        iis_entries = [e for e in log_entries if e.get('log_type') == 'iis_access']
        protocol_counts = {}
        
        for entry in iis_entries:
            protocol = entry.get('http_version', 'Unknown')
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        result = []
        for protocol, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
            result.append({
                'http_version': protocol,
                'request_count': count,
                'percentage': round(count / len(iis_entries) * 100, 2) if iis_entries else 0
            })
        
        return result