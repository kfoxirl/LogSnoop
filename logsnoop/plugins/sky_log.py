"""
SKY Binary Log Plugin
Parses SKY binary log files (network traffic data)
"""

import struct
import socket
from datetime import datetime
from typing import Dict, List, Any, Union
from collections import defaultdict
from .base import BaseLogPlugin


class SKYLogPlugin(BaseLogPlugin):
    """Plugin for parsing SKY binary log files."""
    
    @property
    def name(self) -> str:
        return "sky_log"
    
    @property
    def description(self) -> str:
        return "Parser for SKY binary log files (network traffic data)"
    
    @property
    def supported_queries(self) -> List[str]:
        return [
            "traffic_by_ip",
            "top_talkers", 
            "top_data_senders",
            "busiest_day",
            "traffic_summary",
            "bytes_by_source",
            "bytes_by_destination",
            "connections_by_source",
            "connections_by_destination",
            "traffic_timeline",
            "ip_pairs",
            "bandwidth_usage"
        ]
    
    def parse(self, log_content: Union[str, bytes]) -> Dict[str, Any]:
        """Parse SKY binary log content."""
        # Convert string content to bytes if needed
        if isinstance(log_content, str):
            # If it's a string, assume it's base64 encoded or similar
            # For actual binary files, this would be handled differently
            try:
                import base64
                binary_data = base64.b64decode(log_content)
            except:
                # If not base64, convert string to bytes
                binary_data = log_content.encode('latin-1')
        else:
            binary_data = log_content
        
        entries = []
        stats = defaultdict(lambda: 0)
        
        try:
            # Parse header
            header_info = self._parse_header(binary_data)
            
            # Parse body entries
            body_offset = header_info['body_offset']
            num_entries = header_info['num_entries']
            
            # Each entry is 16 bytes (4 ints: src_ip, dst_ip, timestamp, bytes)
            entry_size = 16
            
            for i in range(num_entries):
                offset = body_offset + (i * entry_size)
                
                if offset + entry_size > len(binary_data):
                    break  # Not enough data for complete entry
                
                # Unpack entry: 4 big-endian unsigned integers
                src_ip_int, dst_ip_int, timestamp_int, bytes_transferred = struct.unpack(
                    '>IIII', binary_data[offset:offset + entry_size]
                )
                
                # Convert IP integers to dotted decimal notation
                src_ip = self._int_to_ip(src_ip_int)
                dst_ip = self._int_to_ip(dst_ip_int)
                
                # Convert timestamp to UTC ISO format
                timestamp = datetime.utcfromtimestamp(timestamp_int).isoformat() + 'Z'
                
                entry = {
                    'line_number': i + 1,
                    'raw_line': f"Entry {i+1}: {src_ip} -> {dst_ip} ({bytes_transferred} bytes)",
                    'timestamp': timestamp,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'bytes_transferred': bytes_transferred,
                    'event_type': 'network_transfer',
                    'status': 'completed'
                }
                
                entries.append(entry)
                
                # Update statistics
                stats['total_transfers'] += 1
                stats['total_bytes'] += bytes_transferred
                
            # Calculate additional statistics
            unique_sources = set(entry.get('source_ip') for entry in entries)
            unique_destinations = set(entry.get('destination_ip') for entry in entries)
            
            additional_stats = {
                'total_entries': len(entries),
                'unique_source_ips': len(unique_sources),
                'unique_destination_ips': len(unique_destinations),
                'creation_timestamp': header_info.get('creation_timestamp'),
                'hostname': header_info.get('hostname'),
                'flag': header_info.get('flag'),
                'decoded_flag': header_info.get('decoded_flag'),
                'version': header_info.get('version')
            }
            
            # Merge stats
            final_stats = dict(stats)
            final_stats.update(additional_stats)
            
        except Exception as e:
            # If parsing fails, return minimal info
            final_stats = {
                'parse_error': str(e),
                'total_entries': 0,
                'total_bytes': 0
            }
        
        return {
            'entries': entries,
            'summary': final_stats
        }
    
    def _parse_header(self, binary_data: bytes) -> Dict[str, Any]:
        """Parse the SKY file header."""
        offset = 0
        
        # Magic bytes (8 bytes)
        magic = binary_data[offset:offset + 8]
        expected_magic = b'\x91SKY\r\n\x1a\n'
        if magic != expected_magic:
            raise ValueError(f"Invalid magic bytes. Expected {expected_magic.hex()}, got {magic.hex()}")
        offset += 8
        
        # Version (1 byte)
        version = binary_data[offset]
        if version != 1:
            raise ValueError(f"Unsupported version: {version}")
        offset += 1
        
        # Creation timestamp (4 bytes, big-endian)
        creation_timestamp_int = struct.unpack('>I', binary_data[offset:offset + 4])[0]
        creation_timestamp_utc = datetime.utcfromtimestamp(creation_timestamp_int).isoformat() + 'Z'
        offset += 4
        
        # Hostname length (4 bytes, big-endian)
        hostname_length = struct.unpack('>I', binary_data[offset:offset + 4])[0]
        offset += 4
        
        # Hostname (variable length)
        hostname = binary_data[offset:offset + hostname_length].decode('utf-8') if hostname_length > 0 else ""
        offset += hostname_length
        
        # Flag length (4 bytes, big-endian)
        flag_length = struct.unpack('>I', binary_data[offset:offset + 4])[0]
        offset += 4
        
        # Flag (variable length)
        flag = binary_data[offset:offset + flag_length].decode('utf-8', errors='ignore') if flag_length > 0 else ""
        offset += flag_length
        
        # Try to decode flag if it appears to be Base64
        decoded_flag = self._decode_flag(flag) if flag else ""
        
        # Number of entries (4 bytes, big-endian)
        num_entries = struct.unpack('>I', binary_data[offset:offset + 4])[0]
        offset += 4
        
        return {
            'version': version,
            'creation_timestamp': creation_timestamp_utc,
            'hostname': hostname,
            'flag': flag,
            'decoded_flag': decoded_flag,
            'num_entries': num_entries,
            'body_offset': offset
        }
    
    def _int_to_ip(self, ip_int: int) -> str:
        """Convert integer IP address to dotted decimal notation."""
        return socket.inet_ntoa(struct.pack('>I', ip_int))
    
    def _decode_flag(self, flag: str) -> str:
        """Attempt to decode the flag if it appears to be Base64 encoded."""
        if not flag:
            return ""
        
        try:
            # Check if it looks like Base64 (alphanumeric + / + = padding)
            import re
            import base64
            
            # Base64 pattern: letters, numbers, +, /, and = for padding
            base64_pattern = r'^[A-Za-z0-9+/]*={0,2}$'
            
            if re.match(base64_pattern, flag) and len(flag) % 4 == 0:
                # Try to decode as Base64
                decoded_bytes = base64.b64decode(flag)
                # Try to decode as UTF-8 text
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                
                # Only return if it looks like readable text
                if decoded_text.isprintable():
                    return decoded_text
                else:
                    # If not printable text, return hex representation
                    return f"0x{decoded_bytes.hex()}"
            
        except Exception:
            # If decoding fails, return original flag
            pass
        
        return flag  # Return original if not Base64 or decoding failed
    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        """Execute queries on SKY log entries."""
        
        if query_type == "traffic_by_ip":
            ip_address = kwargs.get('ip_address')
            if ip_address:
                # Get traffic for specific IP (as source or destination)
                traffic = [entry for entry in log_entries 
                          if entry.get('source_ip') == ip_address or entry.get('destination_ip') == ip_address]
                return traffic
            else:
                # Get traffic counts by all IPs
                ip_counts = defaultdict(int)
                for entry in log_entries:
                    src_ip = entry.get('source_ip')
                    dst_ip = entry.get('destination_ip')
                    if src_ip:
                        ip_counts[src_ip] += 1
                    if dst_ip:
                        ip_counts[dst_ip] += 1
                return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "top_talkers":
            limit = kwargs.get('limit', 10)
            by_bytes = kwargs.get('by_bytes', False)
            
            if by_bytes:
                # Top by bytes transferred
                ip_bytes = defaultdict(int)
                for entry in log_entries:
                    src_ip = entry.get('source_ip')
                    if src_ip:
                        ip_bytes[src_ip] += entry.get('bytes_transferred', 0)
                return dict(sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:limit])
            else:
                # Top by connection count
                ip_counts = defaultdict(int)
                for entry in log_entries:
                    src_ip = entry.get('source_ip')
                    if src_ip:
                        ip_counts[src_ip] += 1
                return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit])
        
        elif query_type == "top_data_senders":
            limit = kwargs.get('limit', 10)
            
            # Calculate total bytes sent by each IP
            ip_bytes = defaultdict(int)
            for entry in log_entries:
                src_ip = entry.get('source_ip')
                if src_ip:
                    ip_bytes[src_ip] += entry.get('bytes_transferred', 0)
            
            # Sort by bytes sent (descending) and return top results
            sorted_ips = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:limit]
            
            return {
                'top_senders': dict(sorted_ips),
                'total_ips': len(ip_bytes),
                'top_sender': {
                    'ip': sorted_ips[0][0] if sorted_ips else None,
                    'bytes_sent': sorted_ips[0][1] if sorted_ips else 0
                }
            }
        
        elif query_type == "busiest_day":
            # Group traffic by day and find the day with most bytes transferred
            daily_bytes = defaultdict(lambda: {'bytes': 0, 'connections': 0})
            
            for entry in log_entries:
                timestamp = entry.get('timestamp')
                bytes_transferred = entry.get('bytes_transferred', 0)
                
                if timestamp:
                    try:
                        # Handle both formats: with Z suffix (UTC) and without
                        timestamp_str = timestamp.rstrip('Z')
                        dt = datetime.fromisoformat(timestamp_str)
                        day_key = dt.strftime('%Y-%m-%d')
                        
                        daily_bytes[day_key]['bytes'] += bytes_transferred
                        daily_bytes[day_key]['connections'] += 1
                    except:
                        continue
            
            if not daily_bytes:
                return {
                    'busiest_day': None,
                    'total_bytes': 0,
                    'total_connections': 0,
                    'total_days': 0,
                    'daily_breakdown': {}
                }
            
            # Find the busiest day (by bytes)
            sorted_days = sorted(daily_bytes.items(), key=lambda x: x[1]['bytes'], reverse=True)
            busiest_day, busiest_stats = sorted_days[0]
            
            return {
                'busiest_day': busiest_day,
                'total_bytes': busiest_stats['bytes'],
                'total_connections': busiest_stats['connections'],
                'total_days': len(daily_bytes),
                'daily_breakdown': dict(sorted_days)
            }
        
        elif query_type == "traffic_summary":
            total_bytes = sum(entry.get('bytes_transferred', 0) for entry in log_entries)
            total_connections = len(log_entries)
            unique_sources = len(set(entry.get('source_ip') for entry in log_entries if entry.get('source_ip')))
            unique_destinations = len(set(entry.get('destination_ip') for entry in log_entries if entry.get('destination_ip')))
            
            return {
                'total_connections': total_connections,
                'total_bytes': total_bytes,
                'unique_source_ips': unique_sources,
                'unique_destination_ips': unique_destinations,
                'average_bytes_per_connection': total_bytes / total_connections if total_connections > 0 else 0
            }
        
        elif query_type == "bytes_by_source":
            source_bytes = defaultdict(int)
            for entry in log_entries:
                src_ip = entry.get('source_ip')
                if src_ip:
                    source_bytes[src_ip] += entry.get('bytes_transferred', 0)
            return dict(sorted(source_bytes.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "bytes_by_destination":
            dest_bytes = defaultdict(int)
            for entry in log_entries:
                dst_ip = entry.get('destination_ip')
                if dst_ip:
                    dest_bytes[dst_ip] += entry.get('bytes_transferred', 0)
            return dict(sorted(dest_bytes.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "connections_by_source":
            source_counts = defaultdict(int)
            for entry in log_entries:
                src_ip = entry.get('source_ip')
                if src_ip:
                    source_counts[src_ip] += 1
            return dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "connections_by_destination":
            dest_counts = defaultdict(int)
            for entry in log_entries:
                dst_ip = entry.get('destination_ip')
                if dst_ip:
                    dest_counts[dst_ip] += 1
            return dict(sorted(dest_counts.items(), key=lambda x: x[1], reverse=True))
        
        elif query_type == "traffic_timeline":
            # Group traffic by time period
            period = kwargs.get('period', 'hour')  # hour, day, month
            timeline = defaultdict(lambda: {'connections': 0, 'bytes': 0})
            
            for entry in log_entries:
                timestamp = entry.get('timestamp')
                bytes_transferred = entry.get('bytes_transferred', 0)
                
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
                        
                        timeline[key]['connections'] += 1
                        timeline[key]['bytes'] += bytes_transferred
                    except:
                        continue
            
            return dict(sorted(timeline.items()))
        
        elif query_type == "ip_pairs":
            # Most common source-destination pairs
            limit = kwargs.get('limit', 10)
            pairs = defaultdict(lambda: {'connections': 0, 'bytes': 0})
            
            for entry in log_entries:
                src_ip = entry.get('source_ip')
                dst_ip = entry.get('destination_ip')
                bytes_transferred = entry.get('bytes_transferred', 0)
                
                if src_ip and dst_ip:
                    pair_key = f"{src_ip} -> {dst_ip}"
                    pairs[pair_key]['connections'] += 1
                    pairs[pair_key]['bytes'] += bytes_transferred
            
            # Sort by connections or bytes
            sort_by = kwargs.get('sort_by', 'connections')
            sorted_pairs = sorted(pairs.items(), key=lambda x: x[1][sort_by], reverse=True)
            
            return dict(sorted_pairs[:limit])
        
        elif query_type == "bandwidth_usage":
            # Bandwidth usage over time
            period = kwargs.get('period', 'hour')
            bandwidth = defaultdict(int)
            
            for entry in log_entries:
                timestamp = entry.get('timestamp')
                bytes_transferred = entry.get('bytes_transferred', 0)
                
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
                        
                        bandwidth[key] += bytes_transferred
                    except:
                        continue
            
            return dict(sorted(bandwidth.items()))
        
        else:
            raise ValueError(f"Unsupported query type: {query_type}")
    
    def parse_binary_file(self, file_path: str) -> Dict[str, Any]:
        """Parse a binary SKY log file directly from disk."""
        with open(file_path, 'rb') as f:
            binary_data = f.read()
        
        # Call parse with bytes directly since our parse method handles both str and bytes
        return self.parse(binary_data)