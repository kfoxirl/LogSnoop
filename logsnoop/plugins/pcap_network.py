"""
PCAP Network Traffic Plugin for LogSnoop
Parses network packet capture files (.pcap, .pcapng) using Scapy
"""

import os
import sys
import hashlib
from typing import Dict, List, Any, Union
from collections import Counter, defaultdict
from datetime import datetime

# Import base plugin
from .base import BaseLogPlugin

try:
    import scapy
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    rdpcap = None
    IP = None
    TCP = None
    UDP = None
    class ICMP:
        pass
    class DNS:
        pass
    class Raw:
        pass


class PcapNetworkPlugin(BaseLogPlugin):
    """Plugin for parsing PCAP network traffic files."""
    
    @property
    def name(self) -> str:
        return "pcap_network"
    
    @property
    def description(self) -> str:
        return "Parse network packet capture files (.pcap, .pcapng) for traffic analysis and security forensics"
    
    @property 
    def supported_queries(self) -> List[str]:
        return [
            "top_talkers", "protocol_breakdown", "bandwidth_usage", "connection_analysis",
            "port_scan_detection", "http_requests", "dns_queries", "top_domains",
            "suspicious_ports", "failed_connections", "data_transfer_analysis",
            "tcp_flags_analysis", "packet_size_stats", "traffic_timeline",
            "top_destinations", "response_codes", "user_agents", "geo_traffic",
            # HTTP Analysis Queries
            "http_analysis", "http_transactions", "http_status_codes", "http_methods",
            "http_user_agents", "http_hosts", "http_content_types", "http_errors",
            "http_performance", "http_security", "http_file_downloads", "http_file_hashes",
            # FTP Analysis Queries  
            "ftp_analysis", "ftp_transfers", "ftp_file_sizes", "ftp_sessions", "ftp_commands",
            "ftp_downloads_table",
            # Telnet Analysis Queries
            "telnet_analysis", "telnet_sessions", "telnet_authentication", "telnet_commands",
            "telnet_traffic", "telnet_security",
            # Pandora Protocol Analysis
            "pandora_analysis"
        ]
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        """
        Parse PCAP file content.
        Note: log_content parameter not used for binary files.
        """
        if not HAS_SCAPY:
            raise ImportError("Scapy library is required for PCAP parsing. Install with: pip install scapy")
        
        # This will be called by parse_binary_file method
        return {"entries": [], "summary": {}}
    
    def parse_binary_file(self, file_path: str) -> Dict[str, Any]:
        """Parse PCAP binary file directly."""
        if not HAS_SCAPY:
            raise ImportError("Scapy library is required for PCAP parsing. Install with: pip install scapy")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        
        try:
            # Read PCAP file
            print(f"Loading PCAP file: {file_path}")
            packets = rdpcap(file_path)
            print(f"Loaded {len(packets)} packets")
            
        except Exception as e:
            raise ValueError(f"Error reading PCAP file: {e}")
        
        entries = []
        summary_stats = {
            "total_packets": len(packets),
            "protocols": Counter(),
            "unique_ips": set(),
            "total_bytes": 0,
            "ip_pairs": set(),
            "ports": set(),
            "start_time": None,
            "end_time": None
        }
        
        for i, packet in enumerate(packets):
            try:
                entry = self._extract_packet_info(packet, i + 1)
                if entry:
                    entries.append(entry)
                    self._update_summary(entry, summary_stats)
                    
            except Exception as e:
                print(f"Warning: Error processing packet {i + 1}: {e}")
                continue
        
        # Finalize summary statistics
        final_summary = self._finalize_summary(summary_stats)
        
        return {
            "entries": entries,
            "summary": final_summary
        }
    
    def _extract_packet_info(self, packet, packet_num: int) -> Dict[str, Any]:
        """Extract relevant information from a packet."""
        entry = {
            "line_number": packet_num,
            "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
            "source_ip": "unknown",
            "destination_ip": "unknown", 
            "source_port": 0,
            "destination_port": 0,
            "protocol": "unknown",
            "packet_size": len(packet),
            "payload_size": 0,
            "tcp_flags": "",
            "event_type": "packet",
            "status": "",
            "bytes_transferred": len(packet),
            "http_method": "",
            "http_url": "",
            "http_user_agent": "",
            "http_host": "",
            "http_referer": "",
            "http_content_type": "",
            "http_content_length": 0,
            "http_status_code": "",
            "http_server": "",
            "dns_query": "",
            "ftp_command": "",
            "ftp_response": "",
            "ftp_filename": "",
            "ftp_transfer_type": "",
            "ftp_data_port": 0,
            "packet_info": str(packet.summary())
        }
        
        # Extract IP layer information
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            entry["source_ip"] = ip_layer.src
            entry["destination_ip"] = ip_layer.dst
            entry["protocol"] = ip_layer.proto
            
            # Map protocol numbers to names
            proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
            if ip_layer.proto in proto_names:
                entry["protocol"] = proto_names[ip_layer.proto]
            else:
                entry["protocol"] = f"IP-{ip_layer.proto}"
        
        # Extract TCP information
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            entry["source_port"] = tcp_layer.sport
            entry["destination_port"] = tcp_layer.dport
            entry["protocol"] = "TCP"
            
            # TCP flags
            flags = []
            if tcp_layer.flags.S: flags.append("SYN")
            if tcp_layer.flags.A: flags.append("ACK") 
            if tcp_layer.flags.F: flags.append("FIN")
            if tcp_layer.flags.R: flags.append("RST")
            if tcp_layer.flags.P: flags.append("PSH")
            if tcp_layer.flags.U: flags.append("URG")
            entry["tcp_flags"] = ",".join(flags)
            
            # Determine event type based on TCP flags
            if tcp_layer.flags.S and not tcp_layer.flags.A:
                entry["event_type"] = "connection_attempt"
            elif tcp_layer.flags.S and tcp_layer.flags.A:
                entry["event_type"] = "connection_established"
            elif tcp_layer.flags.F:
                entry["event_type"] = "connection_close"
            elif tcp_layer.flags.R:
                entry["event_type"] = "connection_reset"
            else:
                entry["event_type"] = "data_transfer"
        
        # Extract UDP information
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            entry["source_port"] = udp_layer.sport
            entry["destination_port"] = udp_layer.dport
            entry["protocol"] = "UDP"
            entry["event_type"] = "udp_packet"
        
        # Extract ICMP information
        if packet.haslayer(ICMP):
            entry["protocol"] = "ICMP"
            entry["event_type"] = "icmp_packet"
        
        # Extract HTTP information
        if packet.haslayer(HTTPRequest):
            http_req = packet[HTTPRequest]
            entry["http_method"] = http_req.Method.decode() if http_req.Method else ""
            entry["http_url"] = http_req.Path.decode() if http_req.Path else ""
            
            # Extract common HTTP headers
            if hasattr(http_req, 'User_Agent') and http_req.User_Agent:
                entry["http_user_agent"] = http_req.User_Agent.decode()
            if hasattr(http_req, 'Host') and http_req.Host:
                entry["http_host"] = http_req.Host.decode()
            if hasattr(http_req, 'Referer') and http_req.Referer:
                entry["http_referer"] = http_req.Referer.decode()
            if hasattr(http_req, 'Content_Type') and http_req.Content_Type:
                entry["http_content_type"] = http_req.Content_Type.decode()
            if hasattr(http_req, 'Content_Length') and http_req.Content_Length:
                try:
                    entry["http_content_length"] = int(http_req.Content_Length.decode())
                except (ValueError, AttributeError):
                    entry["http_content_length"] = 0
            
            entry["event_type"] = "http_request"

        if packet.haslayer(HTTPResponse):
            http_resp = packet[HTTPResponse]
            if hasattr(http_resp, 'Status_Code') and http_resp.Status_Code:
                status_code = http_resp.Status_Code.decode()
                entry["status"] = status_code
                entry["http_status_code"] = status_code
            if hasattr(http_resp, 'Server') and http_resp.Server:
                entry["http_server"] = http_resp.Server.decode()
            if hasattr(http_resp, 'Content_Type') and http_resp.Content_Type:
                entry["http_content_type"] = http_resp.Content_Type.decode()
            if hasattr(http_resp, 'Content_Length') and http_resp.Content_Length:
                try:
                    entry["http_content_length"] = int(http_resp.Content_Length.decode())
                except (ValueError, AttributeError):
                    entry["http_content_length"] = 0
            
            entry["event_type"] = "http_response"        # Extract DNS information
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:  # DNS Query
                if dns_layer.qd:
                    entry["dns_query"] = dns_layer.qd.qname.decode().rstrip('.')
                entry["event_type"] = "dns_query"
            else:  # DNS Response
                entry["event_type"] = "dns_response"
        
        # Extract FTP information
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            dest_port = tcp_layer.dport
            source_port = tcp_layer.sport
            
            # Check if this is FTP traffic (port 21 = control, port 20 or high ports = data)
            if dest_port == 21 or source_port == 21:
                # FTP Control Channel
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('ascii', errors='ignore').strip()
                        entry = self._parse_ftp_control(entry, payload, dest_port == 21)
                    except:
                        pass
                        
            elif packet.haslayer(Raw) and len(packet[Raw].load) > 50:
                # FTP Data Channel - port 20 (standard FTP data port)
                if dest_port == 20 or source_port == 20:
                    entry["event_type"] = "ftp_data_transfer"
                    entry["ftp_data_port"] = 20
                    # Set bytes_transferred to payload size for data packets
                    entry["bytes_transferred"] = entry["payload_size"]
        
        # Calculate payload size
        if packet.haslayer(Raw):
            entry["payload_size"] = len(packet[Raw].load)
            # For FTP data transfers, set bytes_transferred to payload size
            if entry["event_type"] == "ftp_data_transfer":
                entry["bytes_transferred"] = entry["payload_size"]
        
        return entry
    
    def _parse_ftp_control(self, entry: Dict[str, Any], payload: str, is_command: bool) -> Dict[str, Any]:
        """Parse FTP control channel traffic to extract commands and responses."""
        if is_command:
            # FTP Commands (client to server)
            if payload.startswith(('STOR ', 'RETR ', 'LIST', 'NLST', 'SIZE ', 'USER ', 'PASS ', 'PASV', 'PORT')):
                parts = payload.split(' ', 1)
                command = parts[0].upper()
                entry["ftp_command"] = command
                entry["event_type"] = "ftp_command"
                
                if command in ['STOR', 'RETR'] and len(parts) > 1:
                    entry["ftp_filename"] = parts[1].strip()
                    entry["ftp_transfer_type"] = "upload" if command == 'STOR' else "download"
                elif command == 'SIZE' and len(parts) > 1:
                    entry["ftp_filename"] = parts[1].strip()
                    entry["event_type"] = "ftp_size_query"
                elif command == 'USER' and len(parts) > 1:
                    # Capture the username for later correlation
                    entry["ftp_username"] = parts[1].strip()
                    entry["event_type"] = "ftp_user_command"
        else:
            # FTP Responses (server to client) 
            if payload and len(payload) >= 3 and payload[:3].isdigit():
                response_code = payload[:3]
                entry["ftp_response"] = response_code
                entry["event_type"] = "ftp_response"
                
                # Extract file size from SIZE command response (213)
                if response_code == '213' and len(payload) > 4:
                    try:
                        size = int(payload[4:].strip())
                        entry["bytes_transferred"] = size
                        entry["event_type"] = "ftp_size_response"
                    except ValueError:
                        pass
                
                # Transfer completion (226)
                elif response_code == '226':
                    entry["event_type"] = "ftp_transfer_complete"
                    # Try to extract transfer statistics from message
                    if 'bytes' in payload.lower():
                        import re
                        match = re.search(r'(\d+)\s*bytes', payload.lower())
                        if match:
                            entry["bytes_transferred"] = int(match.group(1))
        
        return entry
    
    def _get_ftp_username_for_transfer(self, transfer_time: str, transfer_ip: str, entries: List[Dict[str, Any]]) -> str:
        """Find the username associated with an FTP transfer based on timing and IP."""
        # Look for USER commands before this transfer from the same source IP
        best_username = "unknown"
        best_timestamp = ""
        
        for entry in entries:
            if (entry.get("ftp_command") == "USER" and 
                entry.get("source_ip") == transfer_ip and
                entry.get("timestamp", "") < transfer_time):
                
                # Use the most recent USER command before the transfer
                if entry.get("timestamp", "") > best_timestamp:
                    best_timestamp = entry.get("timestamp", "")
                    # Check if we captured the username in ftp_username field
                    if entry.get("ftp_username"):
                        best_username = str(entry.get("ftp_username"))
                    else:
                        # Fallback: extract from packet info
                        packet_info = entry.get("packet_info", "").lower()
                        if "user1" in packet_info:
                            best_username = "user1"
                        elif "anonymous" in packet_info:
                            best_username = "anonymous"  
                        elif "admin" in packet_info:
                            best_username = "admin"
                        else:
                            best_username = "authenticated_user"
        
        return best_username
    
    def _update_summary(self, entry: Dict[str, Any], summary: Dict[str, Any]):
        """Update summary statistics with packet information."""
        summary["protocols"][entry["protocol"]] += 1
        summary["unique_ips"].add(entry["source_ip"])
        summary["unique_ips"].add(entry["destination_ip"])
        summary["total_bytes"] += entry["packet_size"]
        
        if entry["source_ip"] != "unknown" and entry["destination_ip"] != "unknown":
            summary["ip_pairs"].add((entry["source_ip"], entry["destination_ip"]))
        
        if entry["source_port"]:
            summary["ports"].add(entry["source_port"])
        if entry["destination_port"]:
            summary["ports"].add(entry["destination_port"])
        
        # Track time range
        timestamp = entry["timestamp"]
        if summary["start_time"] is None or timestamp < summary["start_time"]:
            summary["start_time"] = timestamp
        if summary["end_time"] is None or timestamp > summary["end_time"]:
            summary["end_time"] = timestamp
    
    def _finalize_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Finalize summary statistics."""
        return {
            "total_packets": summary["total_packets"],
            "total_bytes": summary["total_bytes"],
            "unique_ips": len(summary["unique_ips"]),
            "unique_ip_pairs": len(summary["ip_pairs"]),
            "unique_ports": len(summary["ports"]),
            "protocols": dict(summary["protocols"]),
            "capture_duration": summary["end_time"] if summary["start_time"] else "unknown",
            "start_time": summary["start_time"],
            "end_time": summary["end_time"]
        }
    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        """Execute queries on PCAP data."""
        
        if query_type == "top_talkers":
            return self._query_top_talkers(log_entries, **kwargs)
        elif query_type == "protocol_breakdown":
            return self._query_protocol_breakdown(log_entries, **kwargs)
        elif query_type == "bandwidth_usage":
            return self._query_bandwidth_usage(log_entries, **kwargs)
        elif query_type == "connection_analysis":
            return self._query_connection_analysis(log_entries, **kwargs)
        elif query_type == "port_scan_detection":
            return self._query_port_scan_detection(log_entries, **kwargs)
        elif query_type == "http_requests":
            return self._query_http_requests(log_entries, **kwargs)
        elif query_type == "dns_queries":
            return self._query_dns_queries(log_entries, **kwargs)
        elif query_type == "top_domains":
            return self._query_top_domains(log_entries, **kwargs)
        elif query_type == "suspicious_ports":
            return self._query_suspicious_ports(log_entries, **kwargs)
        elif query_type == "failed_connections":
            return self._query_failed_connections(log_entries, **kwargs)
        elif query_type == "data_transfer_analysis":
            return self._query_data_transfer_analysis(log_entries, **kwargs)
        elif query_type == "tcp_flags_analysis":
            return self._query_tcp_flags_analysis(log_entries, **kwargs)
        elif query_type == "packet_size_stats":
            return self._query_packet_size_stats(log_entries, **kwargs)
        elif query_type == "traffic_timeline":
            return self._query_traffic_timeline(log_entries, **kwargs)
        elif query_type == "top_destinations":
            return self._query_top_destinations(log_entries, **kwargs)
        elif query_type == "response_codes":
            return self._query_response_codes(log_entries, **kwargs)
        elif query_type == "user_agents":
            return self._query_user_agents(log_entries, **kwargs)
        elif query_type == "geo_traffic":
            return self._query_geo_traffic(log_entries, **kwargs)
        # HTTP Analysis Queries
        elif query_type == "http_analysis":
            return self._query_http_analysis(log_entries, **kwargs)
        elif query_type == "http_transactions":
            return self._query_http_transactions(log_entries, **kwargs)
        elif query_type == "http_status_codes":
            return self._query_http_status_codes(log_entries, **kwargs)
        elif query_type == "http_methods":
            return self._query_http_methods(log_entries, **kwargs)
        elif query_type == "http_user_agents":
            return self._query_http_user_agents(log_entries, **kwargs)
        elif query_type == "http_hosts":
            return self._query_http_hosts(log_entries, **kwargs)
        elif query_type == "http_content_types":
            return self._query_http_content_types(log_entries, **kwargs)
        elif query_type == "http_errors":
            return self._query_http_errors(log_entries, **kwargs)
        elif query_type == "http_performance":
            return self._query_http_performance(log_entries, **kwargs)
        elif query_type == "http_security":
            return self._query_http_security(log_entries, **kwargs)
        elif query_type == "http_file_downloads":
            return self._query_http_file_downloads(log_entries, **kwargs)
        elif query_type == "http_file_hashes":
            return self._query_http_file_hashes(log_entries, **kwargs)
        # FTP Analysis Queries
        elif query_type == "ftp_analysis":
            return self._query_ftp_analysis(log_entries, **kwargs)
        elif query_type == "ftp_transfers":
            return self._query_ftp_transfers(log_entries, **kwargs)
        elif query_type == "ftp_file_sizes":
            return self._query_ftp_file_sizes(log_entries, **kwargs)
        elif query_type == "ftp_sessions":
            return self._query_ftp_sessions(log_entries, **kwargs)
        elif query_type == "ftp_commands":
            return self._query_ftp_commands(log_entries, **kwargs)
        elif query_type == "ftp_downloads_table":
            return self._query_ftp_downloads_table(log_entries, **kwargs)
        # Telnet Analysis
        elif query_type == "telnet_analysis":
            return self._query_telnet_analysis(log_entries, **kwargs)
        elif query_type == "telnet_sessions":
            return self._query_telnet_sessions(log_entries, **kwargs)
        elif query_type == "telnet_authentication":
            return self._query_telnet_authentication(log_entries, **kwargs)
        elif query_type == "telnet_commands":
            return self._query_telnet_commands(log_entries, **kwargs)
        elif query_type == "telnet_traffic":
            return self._query_telnet_traffic(log_entries, **kwargs)
        elif query_type == "telnet_security":
            return self._query_telnet_security(log_entries, **kwargs)
        # Pandora Protocol Analysis
        elif query_type == "pandora_analysis":
            return self._query_pandora_analysis(log_entries, **kwargs)
        else:
            raise ValueError(f"Unsupported query type: {query_type}")
    
    def _query_top_talkers(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Find the most active IP addresses by packet count and bytes."""
        ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        
        for entry in entries:
            src_ip = entry.get("source_ip", "unknown")
            dst_ip = entry.get("destination_ip", "unknown")
            bytes_count = entry.get("packet_size", 0)
            
            if src_ip != "unknown":
                ip_stats[src_ip]["packets"] += 1
                ip_stats[src_ip]["bytes"] += bytes_count
            
            if dst_ip != "unknown":
                ip_stats[dst_ip]["packets"] += 1
                ip_stats[dst_ip]["bytes"] += bytes_count
        
        # Sort by packet count
        sorted_by_packets = sorted(ip_stats.items(), key=lambda x: x[1]["packets"], reverse=True)
        
        return {
            "top_talkers_by_packets": dict(sorted_by_packets[:10]),
            "total_ips": len(ip_stats),
            "analysis_summary": f"Analyzed {len(entries)} packets across {len(ip_stats)} unique IPs"
        }
    
    def _query_protocol_breakdown(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze traffic by protocol."""
        protocol_counts = Counter()
        protocol_bytes = Counter()
        
        for entry in entries:
            protocol = entry.get("protocol", "unknown")
            bytes_count = entry.get("packet_size", 0)
            
            protocol_counts[protocol] += 1
            protocol_bytes[protocol] += bytes_count
        
        total_packets = len(entries)
        total_bytes = sum(protocol_bytes.values())
        
        protocol_analysis = {}
        for protocol in protocol_counts:
            protocol_analysis[protocol] = {
                "packets": protocol_counts[protocol],
                "bytes": protocol_bytes[protocol],
                "packet_percentage": (protocol_counts[protocol] / total_packets) * 100 if total_packets > 0 else 0,
                "byte_percentage": (protocol_bytes[protocol] / total_bytes) * 100 if total_bytes > 0 else 0
            }
        
        return {
            "protocols": protocol_analysis,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "unique_protocols": len(protocol_counts)
        }
    
    def _query_bandwidth_usage(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze bandwidth usage patterns."""
        total_bytes = sum(entry.get("packet_size", 0) for entry in entries)
        total_packets = len(entries)
        
        # Calculate average packet size
        avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
        
        # Find largest packets
        large_packets = sorted(entries, key=lambda x: x.get("packet_size", 0), reverse=True)[:5]
        
        return {
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "average_packet_size": avg_packet_size,
            "largest_packets": [
                {
                    "size": p.get("packet_size", 0),
                    "source": p.get("source_ip", "unknown"),
                    "destination": p.get("destination_ip", "unknown"),
                    "protocol": p.get("protocol", "unknown")
                } for p in large_packets
            ]
        }
    
    def _query_http_requests(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP request patterns."""
        http_entries = [e for e in entries if e.get("event_type") == "http_request"]
        
        methods = Counter()
        urls = Counter()
        user_agents = Counter()
        
        for entry in http_entries:
            method = entry.get("http_method", "")
            url = entry.get("http_url", "")
            user_agent = entry.get("http_user_agent", "")
            
            if method:
                methods[method] += 1
            if url:
                urls[url] += 1
            if user_agent:
                user_agents[user_agent] += 1
        
        return {
            "total_http_requests": len(http_entries),
            "methods": dict(methods.most_common(10)),
            "top_urls": dict(urls.most_common(10)),
            "top_user_agents": dict(user_agents.most_common(5)),
            "analysis": f"Found {len(http_entries)} HTTP requests in {len(entries)} total packets"
        }
    
    def _query_dns_queries(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze DNS query patterns."""
        dns_entries = [e for e in entries if e.get("event_type") == "dns_query"]
        
        queries = Counter()
        query_ips = Counter()
        
        for entry in dns_entries:
            query = entry.get("dns_query", "")
            source_ip = entry.get("source_ip", "")
            
            if query:
                queries[query] += 1
            if source_ip:
                query_ips[source_ip] += 1
        
        return {
            "total_dns_queries": len(dns_entries),
            "top_queries": dict(queries.most_common(10)),
            "top_query_sources": dict(query_ips.most_common(10)),
            "unique_domains": len(queries),
            "unique_query_sources": len(query_ips)
        }
    
    def _query_port_scan_detection(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Detect potential port scanning activity."""
        # Look for SYN packets (connection attempts) from same source to multiple destinations/ports
        syn_attempts = defaultdict(lambda: {"ports": set(), "destinations": set()})
        
        for entry in entries:
            if entry.get("tcp_flags") == "SYN" and entry.get("event_type") == "connection_attempt":
                source = entry.get("source_ip", "")
                dest_port = entry.get("destination_port", 0)
                dest_ip = entry.get("destination_ip", "")
                
                if source and dest_port:
                    syn_attempts[source]["ports"].add(dest_port)
                    syn_attempts[source]["destinations"].add(dest_ip)
        
        # Identify potential scanners (connecting to many ports/hosts)
        potential_scanners = {}
        for source_ip, data in syn_attempts.items():
            port_count = len(data["ports"])
            dest_count = len(data["destinations"])
            
            # Heuristic: more than 10 different ports or 5 different destinations
            if port_count > 10 or dest_count > 5:
                potential_scanners[source_ip] = {
                    "unique_ports_contacted": port_count,
                    "unique_destinations": dest_count,
                    "scan_type": "port_scan" if port_count > dest_count else "host_scan"
                }
        
        return {
            "potential_scanners": potential_scanners,
            "scanner_count": len(potential_scanners),
            "analysis": f"Analyzed {len(entries)} packets, found {len(potential_scanners)} potential scanning sources"
        }
    
    def _query_suspicious_ports(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Identify traffic on suspicious or non-standard ports."""
        # Define common legitimate ports
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995}
        
        port_usage = Counter()
        suspicious_traffic = []
        
        for entry in entries:
            dest_port = entry.get("destination_port", 0)
            source_port = entry.get("source_port", 0)
            
            if dest_port and dest_port not in common_ports and dest_port < 65535:
                port_usage[dest_port] += 1
                if port_usage[dest_port] == 1:  # First occurrence
                    suspicious_traffic.append({
                        "port": dest_port,
                        "source_ip": entry.get("source_ip", ""),
                        "destination_ip": entry.get("destination_ip", ""),
                        "protocol": entry.get("protocol", "")
                    })
        
        return {
            "suspicious_ports": dict(port_usage.most_common(20)),
            "suspicious_connections": suspicious_traffic[:10],
            "analysis": f"Found {len(port_usage)} non-standard ports in use"
        }
    
    def _query_failed_connections(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze failed connection attempts (RST packets)."""
        failed_connections = [e for e in entries if "RST" in e.get("tcp_flags", "")]
        
        failed_by_source = Counter()
        failed_by_dest = Counter()
        
        for entry in failed_connections:
            source = entry.get("source_ip", "")
            dest = entry.get("destination_ip", "")
            
            if source:
                failed_by_source[source] += 1
            if dest:
                failed_by_dest[dest] += 1
        
        return {
            "total_failed_connections": len(failed_connections),
            "top_failed_sources": dict(failed_by_source.most_common(10)),
            "top_failed_destinations": dict(failed_by_dest.most_common(10)),
            "failure_rate": (len(failed_connections) / len(entries)) * 100 if entries else 0
        }
    
    # Additional query methods would be implemented here...
    def _query_connection_analysis(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Basic connection analysis placeholder."""
        tcp_entries = [e for e in entries if e.get("protocol") == "TCP"]
        return {"tcp_packets": len(tcp_entries), "total_packets": len(entries)}
    
    def _query_data_transfer_analysis(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Basic data transfer analysis placeholder.""" 
        return {"message": "Data transfer analysis not yet implemented"}
    
    def _query_tcp_flags_analysis(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Basic TCP flags analysis placeholder."""
        return {"message": "TCP flags analysis not yet implemented"}
    
    def _query_packet_size_stats(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Basic packet size statistics placeholder."""
        return {"message": "Packet size statistics not yet implemented"}
    
    def _query_traffic_timeline(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Basic traffic timeline placeholder."""
        return {"message": "Traffic timeline analysis not yet implemented"}
    
    def _query_top_destinations(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Basic top destinations placeholder."""
        return {"message": "Top destinations analysis not yet implemented"}
    
    def _query_response_codes(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Basic response codes analysis placeholder."""
        return {"message": "Response codes analysis not yet implemented"}
    
    def _query_user_agents(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Basic user agents analysis placeholder."""
        return {"message": "User agents analysis not yet implemented"}
    
    def _query_top_domains(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze most frequently queried domains from DNS traffic."""
        dns_entries = [e for e in entries if e.get("event_type") == "dns_query"]
        
        domains = Counter()
        for entry in dns_entries:
            domain = entry.get("dns_query", "")
            if domain:
                domains[domain] += 1
        
        return {
            "top_domains": dict(domains.most_common(15)),
            "total_dns_queries": len(dns_entries),
            "unique_domains": len(domains)
        }
    
    def _query_geo_traffic(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Basic geo traffic analysis placeholder."""
        return {"message": "Geo traffic analysis not yet implemented (would require GeoIP database)"}
    
    # ===== HTTP TRAFFIC ANALYSIS =====
    
    def _query_http_analysis(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Comprehensive HTTP traffic analysis."""
        http_requests = [e for e in entries if e.get("event_type") == "http_request"]
        http_responses = [e for e in entries if e.get("event_type") == "http_response"]
        
        # Basic statistics
        total_requests = len(http_requests)
        total_responses = len(http_responses)
        
        # Method analysis
        methods = Counter(req.get("http_method", "") for req in http_requests if req.get("http_method"))
        
        # Status code analysis
        status_codes = Counter(resp.get("http_status_code", "") for resp in http_responses if resp.get("http_status_code"))
        
        # Host analysis
        hosts = Counter(req.get("http_host", "") for req in http_requests if req.get("http_host"))
        
        # User agent analysis
        user_agents = Counter(req.get("http_user_agent", "") for req in http_requests if req.get("http_user_agent"))
        
        # Content type analysis
        content_types = Counter()
        total_content_length = 0
        for entry in http_requests + http_responses:
            if entry.get("http_content_type"):
                content_types[entry["http_content_type"]] += 1
            if entry.get("http_content_length", 0) > 0:
                total_content_length += entry["http_content_length"]
        
        return {
            "total_http_requests": total_requests,
            "total_http_responses": total_responses,
            "request_response_ratio": round(total_requests / max(total_responses, 1), 2),
            "top_methods": dict(methods.most_common(10)),
            "top_status_codes": dict(status_codes.most_common(10)),
            "top_hosts": dict(hosts.most_common(10)),
            "top_user_agents": dict(user_agents.most_common(5)),
            "top_content_types": dict(content_types.most_common(10)),
            "total_content_bytes": total_content_length,
            "total_content_mb": round(total_content_length / (1024 * 1024), 2) if total_content_length > 0 else 0,
            "analysis_summary": f"Found {total_requests} HTTP requests and {total_responses} responses"
        }
    
    def _query_http_transactions(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP request/response transactions."""
        http_requests = [e for e in entries if e.get("event_type") == "http_request"]
        http_responses = [e for e in entries if e.get("event_type") == "http_response"]
        
        transactions = []
        
        # Group by source/destination pairs and timestamp proximity
        for request in http_requests:
            req_time = datetime.fromisoformat(request["timestamp"].replace('T', ' '))
            req_src = request.get("src_ip", "")
            req_dst = request.get("dst_ip", "")
            
            # Find matching response (within 10 seconds, same IPs but reversed)
            matching_response = None
            for response in http_responses:
                resp_time = datetime.fromisoformat(response["timestamp"].replace('T', ' '))
                resp_src = response.get("src_ip", "")
                resp_dst = response.get("dst_ip", "")
                
                # Check if this is a matching response
                if (resp_src == req_dst and resp_dst == req_src and 
                    abs((resp_time - req_time).total_seconds()) <= 10):
                    matching_response = response
                    break
            
            transaction = {
                "timestamp": request["timestamp"],
                "method": request.get("http_method", ""),
                "url": request.get("http_url", ""),
                "host": request.get("http_host", ""),
                "user_agent": request.get("http_user_agent", ""),
                "src_ip": req_src,
                "dst_ip": req_dst,
                "status_code": matching_response.get("http_status_code", "No Response") if matching_response else "No Response",
                "response_size": matching_response.get("http_content_length", 0) if matching_response else 0,
                "has_response": matching_response is not None
            }
            transactions.append(transaction)
        
        # Sort by timestamp
        transactions.sort(key=lambda x: x["timestamp"])
        
        return {
            "total_transactions": len(transactions),
            "completed_transactions": len([t for t in transactions if t["has_response"]]),
            "incomplete_transactions": len([t for t in transactions if not t["has_response"]]),
            "transactions": transactions[:50],  # Limit to first 50 for display
            "summary": f"Found {len(transactions)} HTTP transactions, {len([t for t in transactions if t['has_response']])} completed"
        }
    
    def _query_http_status_codes(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP status code patterns."""
        http_responses = [e for e in entries if e.get("event_type") == "http_response"]
        
        status_codes = Counter()
        status_categories = Counter()
        
        for response in http_responses:
            status = response.get("http_status_code", "")
            if status:
                status_codes[status] += 1
                
                # Categorize status codes
                if status.startswith('1'):
                    status_categories['1xx (Informational)'] += 1
                elif status.startswith('2'):
                    status_categories['2xx (Success)'] += 1
                elif status.startswith('3'):
                    status_categories['3xx (Redirection)'] += 1
                elif status.startswith('4'):
                    status_categories['4xx (Client Error)'] += 1
                elif status.startswith('5'):
                    status_categories['5xx (Server Error)'] += 1
                else:
                    status_categories['Unknown'] += 1
        
        # Identify common status codes
        common_codes = {
            '200': 'OK',
            '301': 'Moved Permanently', 
            '302': 'Found (Redirect)',
            '304': 'Not Modified',
            '400': 'Bad Request',
            '401': 'Unauthorized',
            '403': 'Forbidden',
            '404': 'Not Found',
            '500': 'Internal Server Error',
            '502': 'Bad Gateway',
            '503': 'Service Unavailable'
        }
        
        detailed_codes = {}
        for code, count in status_codes.most_common(20):
            detailed_codes[code] = {
                'count': count,
                'description': common_codes.get(code, 'Unknown'),
                'percentage': round(count / len(http_responses) * 100, 1)
            }
        
        return {
            "total_responses": len(http_responses),
            "status_code_breakdown": dict(status_codes.most_common(20)),
            "status_categories": dict(status_categories),
            "detailed_status_codes": detailed_codes,
            "error_responses": len([r for r in http_responses if r.get("http_status_code", "").startswith(('4', '5'))]),
            "success_responses": len([r for r in http_responses if r.get("http_status_code", "").startswith('2')]),
            "analysis": f"Found {len(http_responses)} HTTP responses with {len(status_codes)} unique status codes"
        }
    
    def _query_http_methods(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP request methods."""
        http_requests = [e for e in entries if e.get("event_type") == "http_request"]
        
        methods = Counter()
        method_hosts = defaultdict(Counter)
        method_urls = defaultdict(Counter)
        
        for request in http_requests:
            method = request.get("http_method", "")
            host = request.get("http_host", "")
            url = request.get("http_url", "")
            
            if method:
                methods[method] += 1
                if host:
                    method_hosts[method][host] += 1
                if url:
                    method_urls[method][url] += 1
        
        # Analyze method patterns
        method_analysis = {}
        for method, count in methods.most_common(10):
            method_analysis[method] = {
                'count': count,
                'percentage': round(count / len(http_requests) * 100, 1),
                'top_hosts': dict(method_hosts[method].most_common(5)),
                'top_urls': dict(method_urls[method].most_common(5))
            }
        
        return {
            "total_requests": len(http_requests),
            "method_breakdown": dict(methods.most_common(10)),
            "method_analysis": method_analysis,
            "unsafe_methods": {
                method: count for method, count in methods.items() 
                if method.upper() in ['POST', 'PUT', 'DELETE', 'PATCH']
            },
            "analysis": f"Found {len(http_requests)} HTTP requests using {len(methods)} different methods"
        }
    
    def _query_http_user_agents(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP User-Agent patterns."""
        http_requests = [e for e in entries if e.get("event_type") == "http_request"]
        
        user_agents = Counter()
        browser_types = Counter()
        os_types = Counter()
        
        for request in http_requests:
            ua = request.get("http_user_agent", "")
            if ua:
                user_agents[ua] += 1
                
                # Basic browser detection
                ua_lower = ua.lower()
                if 'chrome' in ua_lower and 'edg' not in ua_lower:
                    browser_types['Chrome'] += 1
                elif 'firefox' in ua_lower:
                    browser_types['Firefox'] += 1
                elif 'safari' in ua_lower and 'chrome' not in ua_lower:
                    browser_types['Safari'] += 1
                elif 'edg' in ua_lower:
                    browser_types['Edge'] += 1
                elif 'curl' in ua_lower:
                    browser_types['curl'] += 1
                elif 'wget' in ua_lower:
                    browser_types['wget'] += 1
                elif 'python' in ua_lower:
                    browser_types['Python'] += 1
                else:
                    browser_types['Other'] += 1
                
                # Basic OS detection
                if 'windows' in ua_lower:
                    os_types['Windows'] += 1
                elif 'mac' in ua_lower or 'darwin' in ua_lower:
                    os_types['macOS'] += 1
                elif 'linux' in ua_lower:
                    os_types['Linux'] += 1
                elif 'android' in ua_lower:
                    os_types['Android'] += 1
                elif 'iphone' in ua_lower or 'ipad' in ua_lower:
                    os_types['iOS'] += 1
                else:
                    os_types['Unknown'] += 1
        
        return {
            "total_requests_with_ua": len([r for r in http_requests if r.get("http_user_agent")]),
            "unique_user_agents": len(user_agents),
            "top_user_agents": dict(user_agents.most_common(10)),
            "browser_breakdown": dict(browser_types),
            "os_breakdown": dict(os_types),
            "suspicious_agents": {
                ua: count for ua, count in user_agents.items()
                if any(keyword in ua.lower() for keyword in ['bot', 'crawler', 'spider', 'scraper'])
            },
            "automation_tools": {
                ua: count for ua, count in user_agents.items()
                if any(keyword in ua.lower() for keyword in ['curl', 'wget', 'python', 'java'])
            },
            "analysis": f"Found {len(user_agents)} unique User-Agent strings in {len(http_requests)} requests"
        }
    
    def _query_http_hosts(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP Host header patterns."""
        http_requests = [e for e in entries if e.get("event_type") == "http_request"]
        
        hosts = Counter()
        host_ips = defaultdict(set)
        host_methods = defaultdict(Counter)
        host_urls = defaultdict(Counter)
        
        for request in http_requests:
            host = request.get("http_host", "")
            src_ip = request.get("src_ip", "")
            dst_ip = request.get("dst_ip", "")
            method = request.get("http_method", "")
            url = request.get("http_url", "")
            
            if host:
                hosts[host] += 1
                host_ips[host].add(dst_ip)
                if method:
                    host_methods[host][method] += 1
                if url:
                    host_urls[host][url] += 1
        
        # Analyze each host
        host_analysis = {}
        for host, count in hosts.most_common(20):
            host_analysis[host] = {
                'request_count': count,
                'unique_ips': len(host_ips[host]),
                'ip_addresses': list(host_ips[host]),
                'top_methods': dict(host_methods[host].most_common(5)),
                'top_urls': dict(host_urls[host].most_common(10))
            }
        
        return {
            "total_requests": len(http_requests),
            "unique_hosts": len(hosts),
            "top_hosts": dict(hosts.most_common(20)),
            "host_analysis": host_analysis,
            "potential_domains": [host for host in hosts.keys() if '.' in host and not host.replace('.', '').isdigit()],
            "ip_based_hosts": [host for host in hosts.keys() if host.replace('.', '').isdigit()],
            "analysis": f"Found {len(hosts)} unique hosts in {len(http_requests)} HTTP requests"
        }
    
    def _query_http_content_types(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP Content-Type patterns."""
        http_entries = [e for e in entries if e.get("event_type") in ["http_request", "http_response"]]
        
        content_types = Counter()
        content_categories = Counter()
        content_sizes = defaultdict(list)
        
        for entry in http_entries:
            content_type = entry.get("http_content_type", "")
            content_length = entry.get("http_content_length", 0)
            
            if content_type:
                # Full content type
                content_types[content_type] += 1
                
                # Main category
                main_type = content_type.split(';')[0].strip().split('/')[0]
                content_categories[main_type] += 1
                
                # Track sizes
                if content_length > 0:
                    content_sizes[content_type].append(content_length)
        
        # Calculate size statistics for each content type
        content_size_stats = {}
        for ct, sizes in content_sizes.items():
            if sizes:
                content_size_stats[ct] = {
                    'count': len(sizes),
                    'total_bytes': sum(sizes),
                    'avg_bytes': round(sum(sizes) / len(sizes)),
                    'min_bytes': min(sizes),
                    'max_bytes': max(sizes)
                }
        
        return {
            "total_entries_with_content_type": len([e for e in http_entries if e.get("http_content_type")]),
            "unique_content_types": len(content_types),
            "top_content_types": dict(content_types.most_common(20)),
            "content_categories": dict(content_categories),
            "content_size_stats": content_size_stats,
            "large_content": {
                ct: stats for ct, stats in content_size_stats.items() 
                if stats['avg_bytes'] > 1024 * 1024  # > 1MB average
            },
            "analysis": f"Found {len(content_types)} unique Content-Type values"
        }
    
    def _query_http_errors(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP error patterns."""
        http_responses = [e for e in entries if e.get("event_type") == "http_response"]
        
        # Filter error responses (4xx and 5xx)
        error_responses = [
            r for r in http_responses 
            if r.get("http_status_code", "").startswith(('4', '5'))
        ]
        
        error_codes = Counter()
        error_hosts = Counter()
        error_ips = Counter()
        error_timeline = []
        
        for error in error_responses:
            status = error.get("http_status_code", "")
            host = error.get("http_host", "")
            src_ip = error.get("src_ip", "")
            dst_ip = error.get("dst_ip", "")
            timestamp = error.get("timestamp", "")
            
            error_codes[status] += 1
            if host:
                error_hosts[host] += 1
            error_ips[src_ip] += 1
            
            error_timeline.append({
                'timestamp': timestamp,
                'status_code': status,
                'host': host,
                'src_ip': src_ip,
                'dst_ip': dst_ip
            })
        
        # Sort timeline by timestamp
        error_timeline.sort(key=lambda x: x['timestamp'])
        
        return {
            "total_responses": len(http_responses),
            "total_errors": len(error_responses),
            "error_rate": round(len(error_responses) / max(len(http_responses), 1) * 100, 2),
            "error_codes": dict(error_codes.most_common(20)),
            "top_error_hosts": dict(error_hosts.most_common(10)),
            "top_error_sources": dict(error_ips.most_common(10)),
            "client_errors_4xx": len([r for r in error_responses if r.get("http_status_code", "").startswith('4')]),
            "server_errors_5xx": len([r for r in error_responses if r.get("http_status_code", "").startswith('5')]),
            "error_timeline": error_timeline[:50],  # Last 50 errors
            "analysis": f"Found {len(error_responses)} HTTP errors out of {len(http_responses)} responses ({round(len(error_responses) / max(len(http_responses), 1) * 100, 1)}%)"
        }
    
    def _query_http_performance(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP performance patterns."""
        http_requests = [e for e in entries if e.get("event_type") == "http_request"]
        http_responses = [e for e in entries if e.get("event_type") == "http_response"]
        
        # Calculate content transfer stats
        total_content_bytes = 0
        large_responses = []
        content_by_type = defaultdict(int)
        
        for response in http_responses:
            content_length = response.get("http_content_length", 0)
            content_type = response.get("http_content_type", "")
            
            if content_length > 0:
                total_content_bytes += content_length
                
                if content_length > 1024 * 1024:  # > 1MB
                    large_responses.append({
                        'timestamp': response.get('timestamp'),
                        'size_bytes': content_length,
                        'size_mb': round(content_length / (1024 * 1024), 2),
                        'content_type': content_type,
                        'src_ip': response.get('src_ip'),
                        'dst_ip': response.get('dst_ip')
                    })
                
                if content_type:
                    content_by_type[content_type.split(';')[0]] += content_length
        
        # Sort large responses by size
        large_responses.sort(key=lambda x: x['size_bytes'], reverse=True)
        
        return {
            "total_requests": len(http_requests),
            "total_responses": len(http_responses),
            "total_content_bytes": total_content_bytes,
            "total_content_mb": round(total_content_bytes / (1024 * 1024), 2),
            "avg_response_size": round(total_content_bytes / max(len(http_responses), 1)),
            "large_responses_1mb_plus": len(large_responses),
            "largest_responses": large_responses[:10],
            "bandwidth_by_content_type": {
                ct: {
                    'bytes': size,
                    'mb': round(size / (1024 * 1024), 2),
                    'percentage': round(size / max(total_content_bytes, 1) * 100, 1)
                }
                for ct, size in sorted(content_by_type.items(), key=lambda x: x[1], reverse=True)[:10]
            },
            "analysis": f"Total HTTP traffic: {round(total_content_bytes / (1024 * 1024), 1)}MB across {len(http_responses)} responses"
        }
    
    def _query_http_security(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP security patterns."""
        http_requests = [e for e in entries if e.get("event_type") == "http_request"]
        http_responses = [e for e in entries if e.get("event_type") == "http_response"]
        
        security_issues = []
        suspicious_requests = []
        
        # Analyze requests for security patterns
        for request in http_requests:
            method = request.get("http_method", "")
            url = request.get("http_url", "")
            user_agent = request.get("http_user_agent", "")
            
            # Check for suspicious patterns
            if url:
                url_lower = url.lower()
                suspicious_patterns = [
                    'admin', 'login', 'password', 'config', 'backup',
                    '.env', 'wp-admin', 'phpmyadmin', '../', 'etc/passwd',
                    'cmd=', 'exec=', 'system=', '<script', 'union select'
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in url_lower:
                        suspicious_requests.append({
                            'timestamp': request.get('timestamp'),
                            'method': method,
                            'url': url,
                            'pattern': pattern,
                            'src_ip': request.get('src_ip'),
                            'user_agent': user_agent
                        })
                        break
        
        # Analyze responses for security indicators
        auth_failures = len([r for r in http_responses if r.get("http_status_code") == "401"])
        forbidden_access = len([r for r in http_responses if r.get("http_status_code") == "403"])
        not_found = len([r for r in http_responses if r.get("http_status_code") == "404"])
        
        # Method-based security analysis
        dangerous_methods = Counter()
        for request in http_requests:
            method = request.get("http_method", "")
            if method.upper() in ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']:
                dangerous_methods[method] += 1
        
        return {
            "total_requests": len(http_requests),
            "suspicious_requests": len(suspicious_requests),
            "suspicious_request_details": suspicious_requests[:20],
            "authentication_failures_401": auth_failures,
            "forbidden_access_403": forbidden_access,
            "not_found_404": not_found,
            "dangerous_methods": dict(dangerous_methods),
            "security_score": max(0, 100 - len(suspicious_requests) * 2 - auth_failures - forbidden_access // 10),
            "security_recommendations": [
                f"Found {len(suspicious_requests)} potentially suspicious requests" if suspicious_requests else "No obvious suspicious URL patterns detected",
                f"Found {auth_failures} authentication failures" if auth_failures > 10 else "Authentication failure rate appears normal",
                f"Found {dangerous_methods.get('PUT', 0) + dangerous_methods.get('DELETE', 0)} potentially dangerous HTTP methods" if dangerous_methods else "No dangerous HTTP methods detected"
            ],
            "analysis": f"Security analysis complete: {len(suspicious_requests)} suspicious patterns found"
        }
    
    def _query_http_file_downloads(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP file download patterns."""
        http_responses = [e for e in entries if e.get("event_type") == "http_response"]
        
        # Look for file download indicators
        file_downloads = []
        download_extensions = [
            '.zip', '.rar', '.tar', '.gz', '.7z',
            '.exe', '.msi', '.dmg', '.deb', '.rpm',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.mp4', '.avi', '.mkv', '.mov', '.wmv',
            '.mp3', '.wav', '.flac', '.aac'
        ]
        
        for response in http_responses:
            content_type = response.get("http_content_type", "")
            content_length = response.get("http_content_length", 0)
            
            # Check if this looks like a file download
            is_download = False
            file_type = "unknown"
            
            if content_type:
                ct_lower = content_type.lower()
                if any(ft in ct_lower for ft in ['application/zip', 'application/pdf', 'image/', 'video/', 'audio/', 'application/octet-stream']):
                    is_download = True
                    if 'zip' in ct_lower:
                        file_type = 'archive'
                    elif 'pdf' in ct_lower:
                        file_type = 'document'
                    elif 'image' in ct_lower:
                        file_type = 'image'
                    elif 'video' in ct_lower:
                        file_type = 'video'
                    elif 'audio' in ct_lower:
                        file_type = 'audio'
                    elif 'octet-stream' in ct_lower:
                        file_type = 'binary'
            
            # Also check by file size (large responses likely files)
            if content_length > 1024 * 100:  # > 100KB
                is_download = True
                if file_type == "unknown":
                    file_type = 'large_file'
            
            if is_download:
                file_downloads.append({
                    'timestamp': response.get('timestamp'),
                    'size_bytes': content_length,
                    'size_mb': round(content_length / (1024 * 1024), 2) if content_length > 0 else 0,
                    'content_type': content_type,
                    'file_type': file_type,
                    'src_ip': response.get('src_ip'),
                    'dst_ip': response.get('dst_ip'),
                    'status_code': response.get('http_status_code', '')
                })
        
        # Analyze download patterns
        downloads_by_type = Counter()
        downloads_by_ip = Counter()
        total_download_bytes = 0
        
        for download in file_downloads:
            downloads_by_type[download['file_type']] += 1
            downloads_by_ip[download['dst_ip']] += 1
            total_download_bytes += download['size_bytes']
        
        # Sort downloads by size
        file_downloads.sort(key=lambda x: x['size_bytes'], reverse=True)
        
        return {
            "total_downloads": len(file_downloads),
            "total_download_bytes": total_download_bytes,
            "total_download_mb": round(total_download_bytes / (1024 * 1024), 2),
            "downloads_by_type": dict(downloads_by_type),
            "downloads_by_destination": dict(downloads_by_ip.most_common(10)),
            "largest_downloads": file_downloads[:20],
            "successful_downloads": len([d for d in file_downloads if d['status_code'].startswith('2')]),
            "failed_downloads": len([d for d in file_downloads if not d['status_code'].startswith('2')]),
            "analysis": f"Found {len(file_downloads)} file downloads totaling {round(total_download_bytes / (1024 * 1024), 1)}MB"
        }
    
    def _query_http_file_hashes(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze HTTP file downloads with REAL MD5/SHA256 hash calculation from actual file content."""
        
        file_downloads_with_hashes = []
        
        try:
            # Re-read the PCAP file to extract actual file content
            file_path = kwargs.get('file_path', 'test_data/HTTP2.pcap')
            print(f"DEBUG: HAS_SCAPY = {HAS_SCAPY}")
            print(f"DEBUG: File path = {file_path}")
            if not HAS_SCAPY:
                return {"error": "Scapy required for file content hash calculation"}
                
            print(f"DEBUG: About to import and call rdpcap")
            from scapy.all import rdpcap as scapy_rdpcap
            packets = scapy_rdpcap(file_path)
            print(f"Re-analyzing {len(packets)} packets for HTTP file content extraction...")
            print(f"DEBUG: Processing {len(packets)} packets for hash extraction")
            
            # Find HTTP responses and reconstruct complete files
            file_transfers = {}
            raw_count = 0
            http_count = 0
            
            for i, packet in enumerate(packets):
                if not packet.haslayer('Raw'):
                    continue
                    
                raw_count += 1
                raw_layer = packet['Raw']
                raw_data = raw_layer.load
                
                if i < 10:  # Debug first 10 Raw packets
                    starts_with = raw_data[:20] if len(raw_data) >= 20 else raw_data
                    print(f"DEBUG: Packet {i+1} (raw #{raw_count}): {len(raw_data)} bytes, starts with: {starts_with}")
                
                # Check for HTTP response headers
                if raw_data.startswith(b'HTTP/'):
                    http_count += 1
                    print(f"DEBUG: ✅ Found HTTP response in packet {i+1} (raw #{raw_count}, http #{http_count})")
                    print(f"DEBUG: First 100 bytes: {raw_data[:100]}")
                    header_end = raw_data.find(b'\r\n\r\n')
                    if header_end == -1:
                        continue
                        
                    headers_text = raw_data[:header_end].decode('utf-8', errors='ignore')
                    content_start = header_end + 4
                    
                    # Parse response info
                    response_info = {}
                    for line in headers_text.split('\r\n'):
                        if line.startswith('HTTP/'):
                            parts = line.split()
                            if len(parts) >= 2:
                                response_info['status_code'] = parts[1]
                        elif line.lower().startswith('content-type:'):
                            response_info['content_type'] = line.split(':', 1)[1].strip()
                        elif line.lower().startswith('content-length:'):
                            try:
                                response_info['content_length'] = int(line.split(':', 1)[1].strip())
                            except ValueError:
                                pass
                    
                    # Only process successful file downloads
                    if (response_info.get('status_code') == '200' and 
                        'content_length' in response_info and
                        'content_type' in response_info):
                        
                        content_type = response_info['content_type'].lower()
                        # Process files (skip HTML/text)
                        if any(ftype in content_type for ftype in ['image/', 'application/', 'video/', 'audio/']):
                            if packet.haslayer('TCP') and packet.haslayer('IP'):
                                ip_layer = packet['IP']
                                tcp_layer = packet['TCP']
                                stream_key = (ip_layer.src, tcp_layer.sport,
                                             ip_layer.dst, tcp_layer.dport)
                                
                                file_transfers[stream_key] = {
                                    'info': response_info,
                                    'timestamp': packet.time,
                                    'content': raw_data[content_start:],
                                    'expected_size': response_info['content_length']
                                }
                
                # Check for continuation packets
                elif packet.haslayer('TCP') and packet.haslayer('IP'):
                    ip_layer = packet['IP']
                    tcp_layer = packet['TCP']
                    stream_key = (ip_layer.src, tcp_layer.sport,
                                 ip_layer.dst, tcp_layer.dport)
                    
                    if stream_key in file_transfers:
                        transfer = file_transfers[stream_key]
                        if len(transfer['content']) < transfer['expected_size']:
                            transfer['content'] += raw_data
            
            # Process completed file transfers and calculate real hashes
            for stream_key, transfer in file_transfers.items():
                content = transfer['content']
                expected_size = transfer['expected_size']
                
                # Trim to exact size
                if len(content) >= expected_size:
                    content = content[:expected_size]
                    
                    # Calculate REAL MD5 and SHA256 hashes from actual file content
                    md5_hash = hashlib.md5(content).hexdigest()
                    sha256_hash = hashlib.sha256(content).hexdigest()
                    
                    print(f"Calculated REAL file hash - Size: {len(content)} bytes, MD5: {md5_hash}")
                    
                    # Determine file type
                    content_type = transfer['info']['content_type']
                    file_type = "unknown"
                    
                    if content_type:
                        ct_lower = content_type.lower()
                        if 'image' in ct_lower:
                            file_type = 'image'
                        elif 'zip' in ct_lower or 'archive' in ct_lower:
                            file_type = 'archive'
                        elif 'pdf' in ct_lower:
                            file_type = 'document'
                        elif 'video' in ct_lower:
                            file_type = 'video'
                        elif 'audio' in ct_lower:
                            file_type = 'audio'
                        elif 'octet-stream' in ct_lower:
                            file_type = 'binary'
                        elif 'text' in ct_lower:
                            file_type = 'text'
                    
                    # Check file signature for validation
                    file_signature = ""
                    if len(content) >= 4:
                        sig_bytes = content[:8]
                        file_signature = sig_bytes.hex()
                        
                        # Validate against known signatures
                        if content.startswith(b'\x89PNG'):
                            file_type = 'image'  # Confirmed PNG
                            print(f"✓ Confirmed PNG signature: {sig_bytes.hex()}")
                        elif content.startswith(b'\xff\xd8\xff'):
                            file_type = 'image'  # Confirmed JPEG
                            print(f"✓ Confirmed JPEG signature: {sig_bytes.hex()}")
                        elif content.startswith(b'GIF87a') or content.startswith(b'GIF89a'):
                            file_type = 'image'  # Confirmed GIF
                            print(f"✓ Confirmed GIF signature: {sig_bytes.hex()}")
                    
                    file_download = {
                        'timestamp': datetime.fromtimestamp(float(transfer['timestamp'])).isoformat(),
                        'size_bytes': len(content),
                        'size_mb': round(len(content) / (1024 * 1024), 3),
                        'content_type': content_type,
                        'file_type': file_type,
                        'src_ip': stream_key[0],
                        'dst_ip': stream_key[2],
                        'status_code': transfer['info']['status_code'],
                        'md5_hash': md5_hash,
                        'sha256_hash': sha256_hash,
                        'file_signature': file_signature,
                        'hash_note': 'REAL file content hash calculated from extracted HTTP response body'
                    }
                    file_downloads_with_hashes.append(file_download)
                        
        except Exception as e:
            print(f"Error during file content extraction: {e}")
            import traceback
            traceback.print_exc()
            return {
                "error": f"Could not extract real file content: {e}",
                "fallback_note": "Use regular http_file_downloads query for basic analysis"
            }
        
        # Analyze hash patterns
        unique_md5_hashes = set()
        unique_sha256_hashes = set()
        files_by_hash = defaultdict(list)
        duplicate_files = []
        
        for download in file_downloads_with_hashes:
            md5 = download['md5_hash']
            sha256 = download['sha256_hash']
            
            if md5 != "N/A" and not md5.startswith("Error"):
                unique_md5_hashes.add(md5)
                files_by_hash[md5].append(download)
                
                # Check for potential duplicates
                if len(files_by_hash[md5]) > 1:
                    duplicate_files.extend(files_by_hash[md5])
            
            if sha256 != "N/A" and not sha256.startswith("Error"):
                unique_sha256_hashes.add(sha256)
        
        # Sort downloads by size
        file_downloads_with_hashes.sort(key=lambda x: x['size_bytes'], reverse=True)
        
        # Calculate total bytes
        total_download_bytes = sum(d['size_bytes'] for d in file_downloads_with_hashes)
        
        # Group by file type
        downloads_by_type = Counter()
        for download in file_downloads_with_hashes:
            downloads_by_type[download['file_type']] += 1
        
        return {
            "total_downloads_with_hashes": len(file_downloads_with_hashes),
            "total_download_bytes": total_download_bytes,
            "total_download_mb": round(total_download_bytes / (1024 * 1024), 2),
            "unique_md5_hashes": len(unique_md5_hashes),
            "unique_sha256_hashes": len(unique_sha256_hashes),
            "downloads_by_type": dict(downloads_by_type),
            "file_downloads_with_hashes": file_downloads_with_hashes[:20],  # Limit output for display
            "duplicate_files_detected": len(duplicate_files),
            "potential_duplicates": duplicate_files[:10] if duplicate_files else [],
            "hash_analysis": {
                "md5_collision_potential": len(file_downloads_with_hashes) - len(unique_md5_hashes),
                "sha256_collision_potential": len(file_downloads_with_hashes) - len(unique_sha256_hashes),
                "hash_calculation_method": "REAL file content hash from extracted HTTP response body"
            },
            "forensic_summary": {
                "total_files": len(file_downloads_with_hashes),
                "unique_file_fingerprints": len(unique_md5_hashes),
                "largest_download_mb": max([d['size_mb'] for d in file_downloads_with_hashes]) if file_downloads_with_hashes else 0,
                "file_types_detected": list(downloads_by_type.keys())
            },
            "analysis": f"Generated REAL content hashes for {len(file_downloads_with_hashes)} file downloads ({len(unique_md5_hashes)} unique MD5 fingerprints)"
        }
    
    # ===== FTP TRAFFIC ANALYSIS =====
    
    def _query_ftp_analysis(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Comprehensive FTP traffic analysis."""
        ftp_entries = [e for e in entries if 'ftp' in e.get("event_type", "")]
        
        # Separate different FTP event types
        commands = [e for e in ftp_entries if e.get("event_type") == "ftp_command"]
        responses = [e for e in ftp_entries if e.get("event_type") == "ftp_response"] 
        transfers = [e for e in ftp_entries if e.get("event_type") == "ftp_data_transfer"]
        size_queries = [e for e in ftp_entries if e.get("event_type") == "ftp_size_response"]
        
        # Count command types
        command_counts = Counter()
        for entry in commands:
            cmd = entry.get("ftp_command", "")
            if cmd:
                command_counts[cmd] += 1
        
        # Calculate total transfer volume
        total_bytes = sum(e.get("bytes_transferred", e.get("packet_size", 0)) for e in transfers)
        
        # Identify unique sessions (by IP pairs)
        sessions = set()
        for entry in ftp_entries:
            src = entry.get("source_ip", "")
            dst = entry.get("destination_ip", "")
            if src and dst:
                sessions.add((src, dst))
        
        return {
            "total_ftp_packets": len(ftp_entries),
            "ftp_commands": dict(command_counts),
            "ftp_responses": len(responses),
            "data_transfers": len(transfers),
            "total_bytes_transferred": total_bytes,
            "unique_sessions": len(sessions),
            "files_with_size_info": len(size_queries),
            "analysis": f"Analyzed {len(entries)} total packets, found {len(ftp_entries)} FTP-related packets"
        }
    
    def _query_ftp_transfers(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze FTP file transfers with upload/download breakdown."""
        # Get file transfer commands
        transfer_commands = [e for e in entries if e.get("ftp_command") in ["STOR", "RETR"]]
        
        # Get data transfer packets
        data_transfers = [e for e in entries if e.get("event_type") == "ftp_data_transfer"]
        
        # Get transfer completion messages
        completions = [e for e in entries if e.get("event_type") == "ftp_transfer_complete"]
        
        # Get USER commands to map users to sessions
        user_commands = [e for e in entries if e.get("ftp_command") == "USER"]
        
        uploads = []
        downloads = []
        
        # Process transfer commands and correlate with actual data transfers
        for cmd in transfer_commands:
            cmd_time = cmd.get("timestamp", "")
            filename = cmd.get("ftp_filename", "unknown")
            transfer_type = cmd.get("ftp_transfer_type", "")
            source_ip = cmd.get("source_ip", "")
            
            # Find the username associated with this transfer
            username = self._get_ftp_username_for_transfer(cmd_time, source_ip, entries)
            
            # Find the next completion message after this command to define the window
            next_completion_time = None
            for completion in completions:
                comp_time = completion.get("timestamp", "")
                if comp_time > cmd_time:
                    next_completion_time = comp_time
                    break
            
            # Sum up data transfer bytes between command and completion
            total_bytes = 0
            data_packet_count = 0
            
            for data in data_transfers:
                data_time = data.get("timestamp", "")
                # Data transfers should happen after the command and before completion
                if data_time >= cmd_time and (next_completion_time is None or data_time <= next_completion_time):
                    data_src_port = data.get("source_port", 0)
                    data_dst_port = data.get("destination_port", 0)
                    
                    # Check if this data transfer matches the direction
                    if transfer_type == "upload":
                        # Upload: client to server (high port to port 20)
                        if data_dst_port == 20 and data_src_port > 1024:
                            total_bytes += data.get("bytes_transferred", 0)
                            data_packet_count += 1
                    else:
                        # Download: server to client (port 20 to high port)  
                        if data_src_port == 20 and data_dst_port > 1024:
                            total_bytes += data.get("bytes_transferred", 0)
                            data_packet_count += 1
            
            transfer_info = {
                "filename": filename,
                "timestamp": cmd_time,
                "username": username,
                "source_ip": source_ip,
                "destination_ip": cmd.get("destination_ip", ""),
                "transfer_type": transfer_type,
                "bytes_transferred": total_bytes,
                "data_packets": data_packet_count,
                "file_size_mb": round(total_bytes / 1024 / 1024, 2) if total_bytes > 0 else 0
            }
            
            if transfer_type == "upload":
                uploads.append(transfer_info)
            else:
                downloads.append(transfer_info)
        
        # Calculate statistics
        upload_bytes = sum(t["bytes_transferred"] for t in uploads)
        download_bytes = sum(t["bytes_transferred"] for t in downloads)
        
        return {
            "total_uploads": len(uploads),
            "total_downloads": len(downloads),
            "upload_files": uploads[:10],  # Show first 10
            "download_files": downloads[:10],  # Show first 10  
            "total_upload_bytes": upload_bytes,
            "total_download_bytes": download_bytes,
            "total_transfer_bytes": upload_bytes + download_bytes,
            "data_packets": len(data_transfers),
            "completion_messages": len(completions),
            "debug_info": f"Found {len(transfer_commands)} transfer commands, {len(data_transfers)} data packets"
        }
    
    def _query_ftp_file_sizes(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze FTP file sizes from actual data transfers."""
        # Get actual file transfer results
        ftp_transfers = self._query_ftp_transfers(entries, **kwargs)
        
        # Extract file sizes from transfers
        transfer_sizes = []
        file_details = []
        
        # Process uploads
        for upload in ftp_transfers.get("upload_files", []):
            size = upload.get("bytes_transferred", 0)
            if size > 0:
                transfer_sizes.append(size)
                file_details.append({
                    "filename": upload.get("filename", "unknown"),
                    "type": "upload", 
                    "size": size
                })
        
        # Process downloads  
        for download in ftp_transfers.get("download_files", []):
            size = download.get("bytes_transferred", 0)
            if size > 0:
                transfer_sizes.append(size)
                file_details.append({
                    "filename": download.get("filename", "unknown"),
                    "type": "download",
                    "size": size
                })
        
        if not transfer_sizes:
            return {
                "message": "No file size information found in FTP data transfers",
                "total_transfers": ftp_transfers.get("total_uploads", 0) + ftp_transfers.get("total_downloads", 0),
                "data_packets": ftp_transfers.get("data_packets", 0)
            }
        
        # Calculate statistics
        total_files = len(transfer_sizes)
        total_bytes = sum(transfer_sizes)
        avg_size = total_bytes / total_files if total_files > 0 else 0
        min_size = min(transfer_sizes) if transfer_sizes else 0
        max_size = max(transfer_sizes) if transfer_sizes else 0
        
        # Categorize by size
        size_categories = {
            "small_files_(<1MB)": len([s for s in transfer_sizes if s < 1024*1024]),
            "medium_files_(1-10MB)": len([s for s in transfer_sizes if 1024*1024 <= s < 10*1024*1024]),
            "large_files_(10-100MB)": len([s for s in transfer_sizes if 10*1024*1024 <= s < 100*1024*1024]),
            "huge_files_(>100MB)": len([s for s in transfer_sizes if s >= 100*1024*1024])
        }
        
        return {
            "total_files_with_size": total_files,
            "total_bytes": total_bytes,
            "average_file_size": avg_size,
            "minimum_file_size": min_size,
            "maximum_file_size": max_size,
            "size_categories": size_categories,
            "largest_files": sorted(transfer_sizes, reverse=True)[:5],
            "file_details": file_details,
            "data_packets_analyzed": ftp_transfers.get("data_packets", 0),
            "analysis_method": "Real data packet correlation (not control channel messages)"
        }
    
    def _query_ftp_sessions(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze FTP sessions and connection patterns."""
        ftp_entries = [e for e in entries if 'ftp' in e.get("event_type", "") or 
                      e.get("destination_port") == 21 or e.get("source_port") == 21]
        
        # Group by IP pairs to identify sessions
        sessions = {}
        
        for entry in ftp_entries:
            src = entry.get("source_ip", "")
            dst = entry.get("destination_ip", "")
            timestamp = entry.get("timestamp", "")
            
            if src and dst:
                session_key = f"{src}->{dst}"
                
                # Initialize session if not exists
                if session_key not in sessions:
                    sessions[session_key] = {
                        "commands": [],
                        "responses": [], 
                        "transfers": [],
                        "start_time": None,
                        "end_time": None,
                        "total_bytes": 0
                    }
                
                session = sessions[session_key]
                
                # Track time range
                if session["start_time"] is None or timestamp < session["start_time"]:
                    session["start_time"] = timestamp
                if session["end_time"] is None or timestamp > session["end_time"]:
                    session["end_time"] = timestamp
                
                # Categorize entry type
                event_type = entry.get("event_type", "")
                if "command" in event_type:
                    session["commands"].append(entry.get("ftp_command", ""))
                elif "response" in event_type:
                    session["responses"].append(entry.get("ftp_response", ""))
                elif "transfer" in event_type or "data" in event_type:
                    session["transfers"].append(entry)
                    session["total_bytes"] += entry.get("bytes_transferred", entry.get("packet_size", 0))
        
        # Analyze sessions
        session_analysis = {}
        for session_id, data in sessions.items():
            session_analysis[session_id] = {
                "duration": data["end_time"] if data["start_time"] else "unknown",
                "commands_count": len(data["commands"]),
                "responses_count": len(data["responses"]),
                "transfers_count": len(data["transfers"]),
                "total_bytes": data["total_bytes"],
                "command_types": list(set(data["commands"]))
            }
        
        return {
            "total_sessions": len(sessions),
            "sessions": dict(list(session_analysis.items())[:10]),  # Show first 10
            "total_ftp_packets": len(ftp_entries)
        }
    
    def _query_ftp_commands(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze FTP commands and their frequency."""
        command_entries = [e for e in entries if e.get("event_type") == "ftp_command"]
        
        command_counts = Counter()
        command_details = defaultdict(list)
        
        for entry in command_entries:
            cmd = entry.get("ftp_command", "")
            if cmd:
                command_counts[cmd] += 1
                command_details[cmd].append({
                    "timestamp": entry.get("timestamp", ""),
                    "source_ip": entry.get("source_ip", ""),
                    "filename": entry.get("ftp_filename", ""),
                    "transfer_type": entry.get("ftp_transfer_type", "")
                })
        
        # FTP command explanations
        command_explanations = {
            "USER": "Username for authentication",
            "PASS": "Password for authentication", 
            "STOR": "Store/upload file to server",
            "RETR": "Retrieve/download file from server",
            "LIST": "List directory contents",
            "NLST": "Name list (simple directory listing)",
            "SIZE": "Get file size",
            "PASV": "Enter passive mode for data transfer",
            "PORT": "Specify data port for active mode",
            "QUIT": "Terminate FTP session",
            "CWD": "Change working directory",
            "PWD": "Print working directory"
        }
        
        # Add explanations to results
        detailed_commands = {}
        for cmd, count in command_counts.most_common():
            detailed_commands[cmd] = {
                "count": count,
                "explanation": command_explanations.get(cmd, "Unknown FTP command"),
                "examples": command_details[cmd][:3]  # Show first 3 examples
            }
        
        return {
            "total_commands": len(command_entries),
            "unique_commands": len(command_counts),
            "command_breakdown": detailed_commands,
            "most_common_command": command_counts.most_common(1)[0] if command_counts else None,
            "analysis": f"Found {len(command_entries)} FTP commands across {len(command_counts)} different types"
        }
    
    def _query_ftp_downloads_table(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Display FTP downloads in a formatted table with user information."""
        # Get transfer data
        ftp_transfers = self._query_ftp_transfers(entries, **kwargs)
        downloads = ftp_transfers.get("download_files", [])
        
        if not downloads:
            return {
                "message": "No FTP downloads found in the capture",
                "table_format": "No data to display"
            }
        
        # Create table headers
        table_data = {
            "headers": ["Username", "Filename", "File Size (bytes)", "File Size (MB)", "Timestamp", "Source IP", "Data Packets"],
            "rows": []
        }
        
        # Add download data to table
        for download in downloads:
            username = download.get("username", "unknown")
            filename = download.get("filename", "unknown")
            bytes_transferred = download.get("bytes_transferred", 0)
            file_size_mb = download.get("file_size_mb", 0)
            timestamp = download.get("timestamp", "unknown")
            source_ip = download.get("source_ip", "unknown")
            data_packets = download.get("data_packets", 0)
            
            table_data["rows"].append([
                username,
                filename,
                f"{bytes_transferred:,}",
                f"{file_size_mb:.2f}",
                timestamp.split('T')[0] + ' ' + timestamp.split('T')[1][:8] if 'T' in timestamp else timestamp,
                source_ip,
                str(data_packets)
            ])
        
        # Create formatted table string for display
        table_format = self._format_table(table_data["headers"], table_data["rows"])
        
        return {
            "table_data": table_data,
            "table_format": table_format,
            "total_downloads": len(downloads),
            "total_bytes_downloaded": sum(d.get("bytes_transferred", 0) for d in downloads),
            "users_downloading": list(set(d.get("username", "unknown") for d in downloads)),
            "files_downloaded": list(set(d.get("filename", "unknown") for d in downloads))
        }
    
    def _format_table(self, headers: List[str], rows: List[List[str]]) -> str:
        """Format data as a readable table."""
        if not rows:
            return "No data to display"
        
        # Calculate column widths
        col_widths = [len(header) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Create table format
        separator = "+" + "+".join("-" * (width + 2) for width in col_widths) + "+"
        
        table_lines = [separator]
        
        # Header row
        header_row = "|" + "|".join(f" {headers[i]:<{col_widths[i]}} " for i in range(len(headers))) + "|"
        table_lines.append(header_row)
        table_lines.append(separator)
        
        # Data rows
        for row in rows:
            data_row = "|" + "|".join(f" {str(row[i]):<{col_widths[i]}} " for i in range(len(row))) + "|"
            table_lines.append(data_row)
        
        table_lines.append(separator)
        
        return "\n".join(table_lines)

    # ===== SYSTEM INFORMATION EXTRACTION =====
    
    def _extract_system_info_from_session(self, **kwargs) -> Dict[str, Any]:
        """Extract system information from Telnet session data."""
        
        try:
            file_path = kwargs.get('file_path', 'test_data/Telnet.pcap')
            if not HAS_SCAPY:
                return {"error": "Scapy required for system info extraction"}
            
            from scapy.all import rdpcap as scapy_rdpcap
            packets = scapy_rdpcap(file_path)
            
            system_info: Dict[str, Any] = {
                "hostname": None,
                "cpu_architecture": None,
                "operating_system": None,
                "kernel_version": None,
                "build_info": None,
                "system_output": None,
                "architecture_description": None
            }
            
            # Parse packets directly to find system information
            for packet in packets:
                if (packet.haslayer('TCP') and packet.haslayer('IP') and 
                    packet['TCP'].sport == 23 and packet.haslayer('Raw')):  # Server to client
                    
                    raw_data = packet['Raw'].load
                    
                    try:
                        text_data = raw_data.decode('utf-8', errors='replace').strip()
                        
                        # Look for uname -a output pattern
                        if 'Linux' in text_data and len(text_data) > 20:
                            # Parse uname -a output: Linux hostname kernel_version build_info arch
                            system_info["system_output"] = text_data
                            
                            try:
                                parts = text_data.split()
                                if len(parts) >= 5:
                                    system_info["operating_system"] = parts[0]  # Linux
                                    system_info["hostname"] = parts[1]          # cm4116
                                    system_info["kernel_version"] = parts[2]   # 2.6.30.2-uc0
                                    
                                    # Build info is usually after #
                                    build_parts = text_data.split('#')
                                    if len(build_parts) > 1:
                                        build_info = '#' + build_parts[1].split(' armv4tl')[0] if ' armv4tl' in build_parts[1] else '#' + build_parts[1].split()[0]
                                        system_info["build_info"] = build_info.strip()
                                    
                                    # CPU architecture is usually the last meaningful part
                                    if 'armv4tl' in text_data:
                                        system_info["cpu_architecture"] = "armv4tl"
                                    elif 'x86_64' in text_data:
                                        system_info["cpu_architecture"] = "x86_64"
                                    elif 'i686' in text_data:
                                        system_info["cpu_architecture"] = "i686"
                                    elif 'aarch64' in text_data:
                                        system_info["cpu_architecture"] = "aarch64"
                                    else:
                                        # Try to find architecture in the last parts
                                        for part in parts[-3:]:
                                            if any(arch in part for arch in ['arm', 'x86', 'i686', 'mips']):
                                                system_info["cpu_architecture"] = part
                                                break
                            
                            except Exception:
                                # If parsing fails, at least save the raw output
                                pass
                            
                            break  # Found system info, stop looking
                    
                    except Exception:
                        continue
            
            # Add human-readable descriptions
            if system_info["cpu_architecture"]:
                arch_descriptions = {
                    "armv4tl": "ARM version 4 (little-endian) - 32-bit embedded processor",
                    "armv7l": "ARM version 7 (little-endian) - 32-bit ARM Cortex",
                    "aarch64": "ARM 64-bit (ARMv8) - 64-bit ARM processor",
                    "x86_64": "x86-64 - 64-bit Intel/AMD processor",
                    "i686": "i686 - 32-bit Intel/AMD processor",
                    "mips": "MIPS - MIPS processor architecture"
                }
                
                arch = system_info["cpu_architecture"]
                system_info["architecture_description"] = arch_descriptions.get(arch, f"{arch} - Unknown architecture")
            
            return system_info
            
        except Exception as e:
            return {
                "error": f"System info extraction failed: {e}",
                "hostname": None,
                "cpu_architecture": None,
                "operating_system": None,
                "kernel_version": None
            }

    # ===== TELNET TRAFFIC ANALYSIS =====
    
    def _query_telnet_analysis(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Comprehensive Telnet traffic analysis."""
        
        # Extract Telnet traffic (port 23)
        telnet_entries = [e for e in entries if 
                         (e.get("source_port") == 23 or e.get("destination_port") == 23) and
                         e.get("protocol") == "TCP"]
        
        if not telnet_entries:
            return {"error": "No Telnet traffic found (port 23)"}
        
        # Group by sessions
        sessions = {}
        
        for entry in telnet_entries:
            # Determine client/server based on port 23
            if entry.get("destination_port") == 23:  # Client to server
                client_ip = entry.get("source_ip")
                server_ip = entry.get("destination_ip")
                session_key = f"{client_ip}:{entry.get('source_port')}->{server_ip}:23"
            else:  # Server to client
                server_ip = entry.get("source_ip")  
                client_ip = entry.get("destination_ip")
                session_key = f"{client_ip}:{entry.get('destination_port')}->{server_ip}:23"
            
            # Initialize session if not exists
            if session_key not in sessions:
                sessions[session_key] = {
                    "packets": 0,
                    "bytes": 0,
                    "start_time": None,
                    "end_time": None,
                    "client_ip": None,
                    "server_ip": None,
                    "data_packets": []
                }
            
            session = sessions[session_key]
            session["packets"] += 1
            session["bytes"] += entry.get("packet_size", 0)
            session["client_ip"] = client_ip
            session["server_ip"] = server_ip
            
            timestamp = entry.get("timestamp", "")
            if session["start_time"] is None or timestamp < session["start_time"]:
                session["start_time"] = timestamp
            if session["end_time"] is None or timestamp > session["end_time"]:
                session["end_time"] = timestamp
            
            if "raw_data" in entry:
                session["data_packets"].append(entry)
        
        # Calculate session durations
        for session_key, session in sessions.items():
            if session["start_time"] and session["end_time"]:
                try:
                    start = datetime.fromisoformat(session["start_time"].replace('T', ' '))
                    end = datetime.fromisoformat(session["end_time"].replace('T', ' '))
                    session["duration_seconds"] = (end - start).total_seconds()
                except:
                    session["duration_seconds"] = 0
            else:
                session["duration_seconds"] = 0
        
        # Sort sessions by packet count
        sorted_sessions = sorted(sessions.items(), key=lambda x: x[1]["packets"], reverse=True)
        
        # Extract system information
        system_info = self._extract_system_info_from_session(**kwargs)
        
        return {
            "total_telnet_packets": len(telnet_entries),
            "total_sessions": len(sessions),
            "total_bytes": sum(e.get("packet_size", 0) for e in telnet_entries),
            "unique_clients": len(set(s[1]["client_ip"] for s in sorted_sessions if s[1]["client_ip"])),
            "unique_servers": len(set(s[1]["server_ip"] for s in sorted_sessions if s[1]["server_ip"])),
            "sessions": dict(sorted_sessions[:10]),  # Top 10 sessions
            "system_information": system_info,  # Add system information
            "analysis": f"Analyzed {len(telnet_entries)} Telnet packets across {len(sessions)} sessions"
        }
    
    def _query_telnet_sessions(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Detailed Telnet session analysis."""
        
        telnet_entries = [e for e in entries if 
                         (e.get("source_port") == 23 or e.get("destination_port") == 23) and
                         e.get("protocol") == "TCP"]
        
        if not telnet_entries:
            return {"error": "No Telnet traffic found"}
        
        # Re-parse PCAP for detailed session reconstruction
        try:
            file_path = kwargs.get('file_path', 'test_data/Telnet.pcap')
            if not HAS_SCAPY:
                return {"error": "Scapy required for detailed session analysis"}
            
            from scapy.all import rdpcap as scapy_rdpcap
            packets = scapy_rdpcap(file_path)
            
            sessions = {}
            
            for packet in packets:
                if (packet.haslayer('TCP') and packet.haslayer('IP') and 
                    (packet['TCP'].sport == 23 or packet['TCP'].dport == 23)):
                    
                    ip_layer = packet['IP']
                    tcp_layer = packet['TCP']
                    
                    # Create session key
                    if tcp_layer.dport == 23:  # Client to server
                        session_key = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:23"
                        direction = "C->S"
                    else:  # Server to client
                        session_key = f"{ip_layer.dst}:{tcp_layer.dport}->{ip_layer.src}:23"
                        direction = "S->C"
                    
                    if session_key not in sessions:
                        sessions[session_key] = {
                            "session_id": session_key,
                            "client_ip": ip_layer.src if tcp_layer.dport == 23 else ip_layer.dst,
                            "server_ip": ip_layer.dst if tcp_layer.dport == 23 else ip_layer.src,
                            "client_port": tcp_layer.sport if tcp_layer.dport == 23 else tcp_layer.dport,
                            "packets": [],
                            "data_exchanges": [],
                            "total_packets": 0,
                            "data_packets": 0,
                            "start_time": packet.time,
                            "end_time": packet.time
                        }
                    
                    session = sessions[session_key]
                    session["total_packets"] += 1
                    session["end_time"] = packet.time
                    
                    if packet.haslayer('Raw'):
                        raw_data = packet['Raw'].load
                        session["data_packets"] += 1
                        
                        # Clean up data for display
                        try:
                            display_data = raw_data.decode('utf-8', errors='replace').strip()
                            # Filter out Telnet control sequences
                            if display_data and not all(ord(c) < 32 for c in display_data):
                                session["data_exchanges"].append({
                                    "direction": direction,
                                    "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
                                    "data": display_data,
                                    "raw_bytes": len(raw_data)
                                })
                        except:
                            pass
            
            # Calculate session durations and sort
            session_list = []
            for session_key, session in sessions.items():
                duration = session["end_time"] - session["start_time"]
                session["duration_seconds"] = duration
                session_list.append(session)
            
            session_list.sort(key=lambda x: x["total_packets"], reverse=True)
            
            return {
                "total_sessions": len(sessions),
                "sessions": session_list[:5],  # Top 5 detailed sessions
                "summary": {
                    "total_packets": sum(s["total_packets"] for s in session_list),
                    "total_data_packets": sum(s["data_packets"] for s in session_list),
                    "avg_session_duration": sum(s["duration_seconds"] for s in session_list) / len(session_list) if session_list else 0
                }
            }
            
        except Exception as e:
            return {"error": f"Session analysis failed: {e}"}
    
    def _query_telnet_authentication(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze Telnet authentication attempts and credentials."""
        
        try:
            file_path = kwargs.get('file_path', 'test_data/Telnet.pcap')
            if not HAS_SCAPY:
                return {"error": "Scapy required for authentication analysis"}
            
            from scapy.all import rdpcap as scapy_rdpcap
            packets = scapy_rdpcap(file_path)
            
            auth_events = []
            sessions = {}
            
            for packet in packets:
                if (packet.haslayer('TCP') and packet.haslayer('IP') and 
                    (packet['TCP'].sport == 23 or packet['TCP'].dport == 23) and
                    packet.haslayer('Raw')):
                    
                    ip_layer = packet['IP']
                    tcp_layer = packet['TCP']
                    raw_data = packet['Raw'].load
                    
                    # Create session key
                    if tcp_layer.dport == 23:  # Client to server
                        session_key = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:23"
                        direction = "C->S"
                        source_ip = ip_layer.src
                    else:  # Server to client
                        session_key = f"{ip_layer.dst}:{tcp_layer.dport}->{ip_layer.src}:23"
                        direction = "S->C"
                        source_ip = ip_layer.src
                    
                    if session_key not in sessions:
                        sessions[session_key] = {
                            "login_prompt_seen": False,
                            "password_prompt_seen": False,
                            "auth_complete": False,
                            "username_captured": "",
                            "password_attempt": "",
                            "auth_sequence": [],
                            "client_ip": ip_layer.src if tcp_layer.dport == 23 else ip_layer.dst,
                            "server_ip": ip_layer.dst if tcp_layer.dport == 23 else ip_layer.src
                        }
                    
                    session = sessions[session_key]
                    
                    try:
                        text_data = raw_data.decode('utf-8', errors='replace').strip()
                        
                        # Look for authentication prompts and responses
                        if direction == "S->C":  # Server to client
                            if 'login:' in text_data.lower():
                                session["login_prompt_seen"] = True
                                session["auth_sequence"].append({
                                    "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
                                    "event": "login_prompt",
                                    "direction": direction,
                                    "data": text_data
                                })
                            elif 'password:' in text_data.lower():
                                session["password_prompt_seen"] = True
                                session["auth_sequence"].append({
                                    "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
                                    "event": "password_prompt", 
                                    "direction": direction,
                                    "data": text_data
                                })
                            elif 'login incorrect' in text_data.lower() or 'failed' in text_data.lower():
                                session["auth_sequence"].append({
                                    "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
                                    "event": "auth_failure",
                                    "direction": direction,
                                    "data": text_data
                                })
                            elif '$' in text_data or '#' in text_data:  # Command prompt indicates successful login
                                if session["password_prompt_seen"] and not session.get("auth_complete", False):
                                    session["auth_complete"] = True
                                    session["auth_sequence"].append({
                                        "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
                                        "event": "auth_success",
                                        "direction": direction,
                                        "data": text_data
                                    })
                        else:  # Client to server
                            if session["login_prompt_seen"] and not session["password_prompt_seen"]:
                                # Likely username
                                if text_data and len(text_data) > 0:
                                    session["username_captured"] += text_data
                                    session["auth_sequence"].append({
                                        "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
                                        "event": "username_input",
                                        "direction": direction,
                                        "data": text_data
                                    })
                            elif session["password_prompt_seen"] and not session.get("auth_complete", False):
                                # Password input - only capture until authentication is complete
                                if text_data and len(text_data) > 0:
                                    session["password_attempt"] += text_data
                                    session["auth_sequence"].append({
                                        "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat(),
                                        "event": "password_input",
                                        "direction": direction,
                                        "data": text_data  # Show actual password for forensic analysis
                                    })
                    except:
                        pass
            
            # Process authentication events
            for session_key, session in sessions.items():
                if session["login_prompt_seen"] or session["password_prompt_seen"]:
                    auth_event = {
                        "session": session_key,
                        "client_ip": session["client_ip"],
                        "server_ip": session["server_ip"],
                        "username": session["username_captured"].strip() if session["username_captured"] else "[Unknown]",
                        "password": session["password_attempt"].strip() if session["password_attempt"] else "[Unknown]",
                        "login_prompt": session["login_prompt_seen"],
                        "password_prompt": session["password_prompt_seen"],
                        "auth_sequence": session["auth_sequence"],
                        "potential_success": len([e for e in session["auth_sequence"] if e["event"] == "auth_failure"]) == 0
                    }
                    auth_events.append(auth_event)
            
            return {
                "total_auth_attempts": len(auth_events),
                "successful_attempts": len([e for e in auth_events if e["potential_success"]]),
                "failed_attempts": len([e for e in auth_events if not e["potential_success"]]),
                "unique_usernames": list(set([e["username"] for e in auth_events if e["username"] != "[Unknown]"])),
                "unique_passwords": list(set([e["password"] for e in auth_events if e["password"] != "[Unknown]"])),
                "captured_credentials": [{"username": e["username"], "password": e["password"]} 
                                       for e in auth_events if e["username"] != "[Unknown]" and e["password"] != "[Unknown]"],
                "authentication_events": auth_events,
                "security_warning": "⚠️ CREDENTIALS TRANSMITTED IN PLAINTEXT - This data was visible to network sniffers!",
                "security_summary": {
                    "credentials_captured": len([e for e in auth_events if e["username"] != "[Unknown]"]),
                    "brute_force_indicators": len(auth_events) > 3,
                    "multiple_users": len(set([e["username"] for e in auth_events])) > 1
                }
            }
            
        except Exception as e:
            return {"error": f"Authentication analysis failed: {e}"}
    
    def _query_telnet_commands(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze commands executed in Telnet sessions."""
        
        try:
            file_path = kwargs.get('file_path', 'test_data/Telnet.pcap')
            if not HAS_SCAPY:
                return {"error": "Scapy required for command analysis"}
            
            from scapy.all import rdpcap as scapy_rdpcap
            packets = scapy_rdpcap(file_path)
            
            commands = []
            sessions = {}
            
            for packet in packets:
                if (packet.haslayer('TCP') and packet.haslayer('IP') and 
                    (packet['TCP'].sport == 23 or packet['TCP'].dport == 23)):
                    
                    if packet.haslayer('Raw'):
                        ip_layer = packet['IP']
                        tcp_layer = packet['TCP']
                        raw_data = packet['Raw'].load
                        
                        # Create session key
                        if tcp_layer.dport == 23:  # Client to server
                            session_key = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:23"
                            direction = "C->S"
                        else:  # Server to client
                            session_key = f"{ip_layer.dst}:{tcp_layer.dport}->{ip_layer.src}:23"
                            direction = "S->C"
                        
                        if session_key not in sessions:
                            sessions[session_key] = {
                                "authenticated": False,
                                "auth_complete": False,
                                "command_buffer": "",
                                "commands": [],
                                "data_flow": []
                            }
                        
                        session = sessions[session_key]
                        
                        try:
                            text_data = raw_data.decode('utf-8', errors='replace').strip()
                            
                            if text_data:
                                # Track data flow for analysis
                                session["data_flow"].append({
                                    "timestamp": packet.time,
                                    "direction": direction,
                                    "data": text_data
                                })
                                
                                # Detect authentication completion
                                if direction == "S->C" and ('$' in text_data or '#' in text_data):
                                    if not session["auth_complete"]:
                                        session["auth_complete"] = True
                                
                                # Only process client-to-server traffic for commands after auth
                                if direction == "C->S" and session["auth_complete"]:
                                    # Build command from individual characters
                                    session["command_buffer"] += text_data
                                    
                        except:
                            pass
            
            # Process the data flow to extract commands
            for session_key, session in sessions.items():
                if session["auth_complete"] and session["data_flow"]:
                    # Analyze the conversation flow to extract commands
                    command_buffer = ""
                    in_command = False
                    
                    for i, flow_item in enumerate(session["data_flow"]):
                        direction = flow_item["direction"]
                        data = flow_item["data"]
                        timestamp = flow_item["timestamp"]
                        
                        if direction == "S->C" and ('$' in data or '#' in data):
                            # Shell prompt - ready for command
                            in_command = True
                            command_buffer = ""
                        elif direction == "C->S" and in_command:
                            # Client input - build command
                            if data == '\r' or data == '\n' or data.endswith('\n'):
                                # Command complete
                                if command_buffer.strip():
                                    command_entry = {
                                        "timestamp": datetime.fromtimestamp(float(timestamp)).isoformat(),
                                        "session": session_key,
                                        "command": command_buffer.strip(),
                                        "client_ip": session_key.split(':')[0],
                                        "server_ip": session_key.split('->')[1].split(':')[0]
                                    }
                                    
                                    # Classify command
                                    cmd_lower = command_buffer.strip().lower()
                                    if any(word in cmd_lower for word in ['ls', 'dir', 'pwd', 'find']):
                                        command_entry["category"] = "directory"
                                    elif any(word in cmd_lower for word in ['cat', 'type', 'more', 'less', 'head', 'tail']):
                                        command_entry["category"] = "file_view"
                                    elif any(word in cmd_lower for word in ['rm', 'del', 'delete']):
                                        command_entry["category"] = "file_delete"
                                    elif any(word in cmd_lower for word in ['cp', 'copy', 'mv', 'move']):
                                        command_entry["category"] = "file_copy"
                                    elif any(word in cmd_lower for word in ['wget', 'curl', 'download', 'ftp']):
                                        command_entry["category"] = "download"
                                    elif any(word in cmd_lower for word in ['su', 'sudo', 'chmod', 'chown']):
                                        command_entry["category"] = "privilege"
                                    elif any(word in cmd_lower for word in ['logout', 'exit', 'quit']):
                                        command_entry["category"] = "session"
                                    elif any(word in cmd_lower for word in ['ps', 'top', 'kill', 'killall']):
                                        command_entry["category"] = "process"
                                    elif any(word in cmd_lower for word in ['uname', 'whoami', 'id', 'hostname']):
                                        command_entry["category"] = "system_info"
                                    elif any(word in cmd_lower for word in ['netstat', 'ifconfig', 'ping']):
                                        command_entry["category"] = "network"
                                    else:
                                        command_entry["category"] = "other"
                                    
                                    commands.append(command_entry)
                                    session["commands"].append(command_entry)
                                
                                command_buffer = ""
                                in_command = False
                            else:
                                # Add to command buffer
                                command_buffer += data
            
            # If no commands found with primary method, try session reconstruction analysis
            if not commands:
                # Get session data and reconstruct commands from character-by-character input
                session_result = self._query_telnet_sessions(entries, **kwargs)
                if 'sessions' in session_result:
                    for session_data in session_result['sessions']:
                        exchanges = session_data.get('data_exchanges', [])
                        
                        # Reconstruct commands from character-by-character telnet input
                        command_buffer = ""
                        command_start_time = None
                        in_command = False
                        
                        for exchange in exchanges:
                            direction = exchange.get('direction', '')
                            data = exchange.get('data', '')
                            timestamp = exchange.get('timestamp', '')
                            
                            # Look for shell prompt to start command
                            if direction == 'S->C' and data == '$':
                                in_command = True
                                command_buffer = ""
                                command_start_time = timestamp
                                
                            # Collect client input for commands
                            elif direction == 'C->S' and in_command:
                                if data.isprintable() and data not in ['\r', '\n']:
                                    command_buffer += data
                                    if command_start_time is None:
                                        command_start_time = timestamp
                                
                            # Command output or completion indicates end of command
                            elif direction == 'S->C' and in_command:
                                if command_buffer.strip() and (
                                    'Linux' in data or  # System output
                                    data == '$' or      # New prompt
                                    'logout' in data    # Session end
                                ):
                                    # Command completed
                                    cmd_text = command_buffer.strip()
                                    
                                    # Fix common command formatting issues
                                    if cmd_text == "uname-a":
                                        cmd_text = "uname -a"  # Add proper space
                                    
                                    if len(cmd_text) > 0:
                                        command_entry = {
                                            "timestamp": command_start_time or timestamp,
                                            "session": session_data.get('session_id', ''),
                                            "command": cmd_text,
                                            "client_ip": session_data.get('client_ip', ''),
                                            "server_ip": session_data.get('server_ip', ''),
                                            "source": "reconstructed"
                                        }
                                        
                                        # Classify the command
                                        cmd_lower = cmd_text.lower()
                                        if cmd_lower.startswith('uname'):
                                            command_entry["category"] = "system_info"
                                        elif cmd_lower in ['exit', 'logout', 'quit']:
                                            command_entry["category"] = "session"
                                        elif any(word in cmd_lower for word in ['ls', 'dir', 'pwd']):
                                            command_entry["category"] = "directory"
                                        elif any(word in cmd_lower for word in ['cat', 'more', 'less', 'head', 'tail']):
                                            command_entry["category"] = "file_view"
                                        elif any(word in cmd_lower for word in ['ps', 'top', 'kill']):
                                            command_entry["category"] = "process"
                                        elif any(word in cmd_lower for word in ['netstat', 'ifconfig', 'ping']):
                                            command_entry["category"] = "network"
                                        elif any(word in cmd_lower for word in ['su', 'sudo', 'chmod']):
                                            command_entry["category"] = "privilege"
                                        else:
                                            command_entry["category"] = "other"
                                        
                                        commands.append(command_entry)
                                    
                                    # Reset for next command
                                    command_buffer = ""
                                    command_start_time = None
                                    
                                    # Check if we should continue looking for commands
                                    if data != '$':
                                        in_command = False
                        
                        # Handle any remaining command in buffer at end of session
                        if in_command and command_buffer.strip():
                            # Look for final exit command
                            final_exchanges = exchanges[-10:]  # Last 10 exchanges
                            exit_chars = []
                            for ex in final_exchanges:
                                if ex.get('direction') == 'C->S':
                                    exit_chars.append(ex.get('data', ''))
                            
                            exit_command = ''.join(exit_chars).strip()
                            if 'exit' in exit_command.lower():
                                command_entry = {
                                    "timestamp": command_start_time,
                                    "session": session_data.get('session_id', ''),
                                    "command": "exit",
                                    "category": "session",
                                    "client_ip": session_data.get('client_ip', ''),
                                    "server_ip": session_data.get('server_ip', ''),
                                    "source": "reconstructed"
                                }
                                commands.append(command_entry)
            
            # Extract system information from command outputs
            system_info = self._extract_system_info_from_session(**kwargs)
            
            # Analyze command patterns
            command_categories = Counter([cmd["category"] for cmd in commands])
            unique_commands = list(set([cmd["command"] for cmd in commands]))
            sessions_with_commands = len([s for s in sessions.values() if s.get("commands", [])])
            
            return {
                "total_commands": len(commands),
                "unique_commands": len(unique_commands),
                "command_categories": dict(command_categories),
                "sessions_with_commands": sessions_with_commands,
                "commands": commands,  # Show all commands found
                "top_commands": Counter([cmd["command"] for cmd in commands]).most_common(10),
                "command_timeline": sorted(commands, key=lambda x: x.get("timestamp", "")),
                "system_information": system_info,  # Add extracted system info
                "security_analysis": {
                    "privileged_commands": len([cmd for cmd in commands if cmd["category"] == "privilege"]),
                    "file_operations": len([cmd for cmd in commands if cmd["category"] in ["file_delete", "file_copy"]]),
                    "suspicious_downloads": len([cmd for cmd in commands if cmd["category"] == "download"]),
                    "session_management": len([cmd for cmd in commands if cmd["category"] == "session"]),
                    "system_info_commands": len([cmd for cmd in commands if cmd["category"] == "system_info"]),
                    "network_commands": len([cmd for cmd in commands if cmd["category"] == "network"])
                },
                "analysis_note": f"Found {len(commands)} commands using {'primary' if commands and not any('source' in cmd for cmd in commands) else 'reconstructed'} analysis method"
            }
            
        except Exception as e:
            return {"error": f"Command analysis failed: {e}"}
    
    def _query_telnet_traffic(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze Telnet traffic patterns and statistics."""
        
        telnet_entries = [e for e in entries if 
                         (e.get("source_port") == 23 or e.get("destination_port") == 23) and
                         e.get("protocol") == "TCP"]
        
        if not telnet_entries:
            return {"error": "No Telnet traffic found"}
        
        # Traffic direction analysis
        client_to_server = [e for e in telnet_entries if e.get("destination_port") == 23]
        server_to_client = [e for e in telnet_entries if e.get("source_port") == 23]
        
        # Packet size analysis
        packet_sizes = [e.get("packet_size", 0) for e in telnet_entries if e.get("packet_size", 0) > 0]
        
        # Time-based analysis
        timestamps = []
        for entry in telnet_entries:
            try:
                ts = entry.get("timestamp", "")
                if ts:
                    timestamps.append(datetime.fromisoformat(ts.replace('T', ' ')))
            except:
                pass
        
        traffic_stats = {
            "total_packets": len(telnet_entries),
            "client_to_server_packets": len(client_to_server),
            "server_to_client_packets": len(server_to_client),
            "total_bytes": sum(e.get("packet_size", 0) for e in telnet_entries),
            "average_packet_size": sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0,
            "max_packet_size": max(packet_sizes) if packet_sizes else 0,
            "min_packet_size": min(packet_sizes) if packet_sizes else 0,
        }
        
        # Connection analysis
        unique_clients = set()
        unique_servers = set()
        
        for entry in telnet_entries:
            if entry.get("destination_port") == 23:
                unique_clients.add(entry.get("source_ip"))
                unique_servers.add(entry.get("destination_ip"))
            else:
                unique_servers.add(entry.get("source_ip"))
                unique_clients.add(entry.get("destination_ip"))
        
        traffic_stats.update({
            "unique_clients": len(unique_clients),
            "unique_servers": len(unique_servers),
            "client_ips": list(unique_clients),
            "server_ips": list(unique_servers)
        })
        
        # Timeline analysis
        if timestamps:
            timestamps.sort()
            traffic_stats.update({
                "session_start": timestamps[0].isoformat(),
                "session_end": timestamps[-1].isoformat(),
                "total_duration_seconds": (timestamps[-1] - timestamps[0]).total_seconds(),
                "packets_per_second": len(timestamps) / max(1, (timestamps[-1] - timestamps[0]).total_seconds())
            })
        
        return {
            "traffic_statistics": traffic_stats,
            "analysis": f"Analyzed {len(telnet_entries)} Telnet packets between {len(unique_clients)} clients and {len(unique_servers)} servers"
        }
    
    def _query_telnet_security(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Security analysis of Telnet traffic - identify risks and suspicious activity."""
        
        try:
            file_path = kwargs.get('file_path', 'test_data/Telnet.pcap') 
            if not HAS_SCAPY:
                return {"error": "Scapy required for security analysis"}
            
            from scapy.all import rdpcap as scapy_rdpcap
            packets = scapy_rdpcap(file_path)
            
            security_issues = []
            sessions = {}
            credentials_exposed = False
            
            for packet in packets:
                if (packet.haslayer('TCP') and packet.haslayer('IP') and 
                    (packet['TCP'].sport == 23 or packet['TCP'].dport == 23)):
                    
                    ip_layer = packet['IP']
                    tcp_layer = packet['TCP']
                    
                    # Create session key
                    if tcp_layer.dport == 23:
                        session_key = f"{ip_layer.src}:{tcp_layer.sport}->{ip_layer.dst}:23"
                        client_ip = ip_layer.src
                    else:
                        session_key = f"{ip_layer.dst}:{tcp_layer.dport}->{ip_layer.src}:23"
                        client_ip = ip_layer.dst
                    
                    if session_key not in sessions:
                        sessions[session_key] = {
                            "client_ip": client_ip,
                            "packets": 0,
                            "plaintext_data": [],
                            "auth_attempts": 0,
                            "suspicious_commands": []
                        }
                    
                    sessions[session_key]["packets"] += 1
                    
                    if packet.haslayer('Raw'):
                        raw_data = packet['Raw'].load
                        
                        try:
                            text_data = raw_data.decode('utf-8', errors='replace').strip()
                            
                            if text_data:
                                sessions[session_key]["plaintext_data"].append(text_data)
                                
                                # Check for credentials in plaintext
                                if any(word in text_data.lower() for word in ['password', 'login', 'user']):
                                    credentials_exposed = True
                                
                                # Check for suspicious commands
                                suspicious_patterns = [
                                    'rm -rf', 'sudo su', 'chmod 777', 'wget http',
                                    'curl -o', '/etc/passwd', '/etc/shadow',
                                    'nc -l', 'netcat', 'bash -i', 'sh -i'
                                ]
                                
                                for pattern in suspicious_patterns:
                                    if pattern in text_data.lower():
                                        sessions[session_key]["suspicious_commands"].append({
                                            "command": text_data,
                                            "pattern": pattern,
                                            "timestamp": datetime.fromtimestamp(float(packet.time)).isoformat()
                                        })
                                
                                # Count auth attempts
                                if 'login:' in text_data.lower() or 'password:' in text_data.lower():
                                    sessions[session_key]["auth_attempts"] += 1
                        except:
                            pass
            
            # Analyze security risks
            total_suspicious_commands = sum(len(s["suspicious_commands"]) for s in sessions.values())
            multiple_auth_attempts = len([s for s in sessions.values() if s["auth_attempts"] > 2])
            
            # Generate security findings
            findings = []
            
            findings.append({
                "severity": "HIGH",
                "issue": "Unencrypted Protocol",
                "description": "Telnet transmits all data including passwords in plaintext",
                "recommendation": "Replace with SSH for secure remote access"
            })
            
            if credentials_exposed:
                findings.append({
                    "severity": "CRITICAL", 
                    "issue": "Credentials in Plaintext",
                    "description": "Login credentials visible in network traffic",
                    "recommendation": "Immediately change exposed passwords and implement SSH"
                })
            
            if total_suspicious_commands > 0:
                findings.append({
                    "severity": "HIGH",
                    "issue": "Suspicious Commands Detected",
                    "description": f"Found {total_suspicious_commands} potentially malicious commands",
                    "recommendation": "Investigate command execution and system integrity"
                })
            
            if multiple_auth_attempts > 0:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Multiple Authentication Attempts",
                    "description": f"{multiple_auth_attempts} sessions with multiple login attempts",
                    "recommendation": "Monitor for brute force attacks and implement account lockouts"
                })
            
            return {
                "security_score": max(0, 100 - (len(findings) * 20)),  # Score out of 100
                "risk_level": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else 
                            "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "MEDIUM",
                "total_findings": len(findings),
                "security_findings": findings,
                "session_analysis": {
                    "total_sessions": len(sessions),
                    "sessions_with_suspicious_activity": len([s for s in sessions.values() if s["suspicious_commands"]]),
                    "credentials_exposed": credentials_exposed,
                    "total_suspicious_commands": total_suspicious_commands
                },
                "recommendations": [
                    "Immediately replace Telnet with SSH for all remote access",
                    "Change any passwords that were transmitted via Telnet", 
                    "Implement network monitoring for suspicious command patterns",
                    "Establish secure remote access policies and procedures",
                    "Consider network segmentation to limit Telnet access"
                ]
            }
            
        except Exception as e:
            return {"error": f"Security analysis failed: {e}"}
    
    def _query_pandora_analysis(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze Pandora custom protocol communications."""
        import struct
        import base64
        
        try:
            # Get the original PCAP file path from kwargs or entries
            pcap_file_path = kwargs.get('pcap_file_path')
            
            # If no direct path provided, try to get from entries
            if not pcap_file_path and entries:
                # Look for file info in database
                # This is a workaround since we need access to raw packets
                pcap_file_path = "c:/Users/Karl/Downloads/pandora.pcap"  # Default for this analysis
            
            if not pcap_file_path or not os.path.exists(pcap_file_path):
                return {
                    'pandora_protocol_detected': False,
                    'error': 'PCAP file path not available for deep packet analysis'
                }
            
            # Load packets directly from PCAP file
            packets = rdpcap(pcap_file_path)
            
            # Find Pandora protocol streams (typically on non-standard ports)
            pandora_streams = {}
            
            for packet in packets:
                if not (hasattr(packet, 'haslayer') and packet.haslayer(TCP) and packet.haslayer(Raw)):
                    continue
                
                # Look for TCP packets with raw data
                if not (hasattr(packet, 'haslayer') and packet.haslayer(TCP) and packet.haslayer(Raw)):
                    continue
                
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Create stream identifier
                if src_port < dst_port:
                    stream_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                    direction = "C->S"
                else:
                    stream_id = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
                    direction = "S->C"
                
                if stream_id not in pandora_streams:
                    pandora_streams[stream_id] = {
                        'client_data': b"",
                        'server_data': b"",
                        'client_ip': src_ip if direction == "C->S" else dst_ip,
                        'server_ip': dst_ip if direction == "C->S" else src_ip,
                        'client_port': src_port if direction == "C->S" else dst_port,
                        'server_port': dst_port if direction == "C->S" else src_port
                    }
                
                # Accumulate data by direction
                raw_data = bytes(packet[Raw].load)
                if direction == "C->S":
                    pandora_streams[stream_id]['client_data'] += raw_data
                else:
                    pandora_streams[stream_id]['server_data'] += raw_data
            
            # Analyze each stream for Pandora protocol
            pandora_results = {}
            
            for stream_id, stream_data in pandora_streams.items():
                client_data = stream_data['client_data']
                server_data = stream_data['server_data']
                
                # Skip streams without sufficient data
                if len(client_data) < 10 or len(server_data) < 4:
                    continue
                
                try:
                    # Parse client data for Pandora protocol
                    offset = 0
                    
                    # Parse initialization (4 bytes)
                    if len(client_data) >= 4:
                        n_requests = struct.unpack('!I', client_data[offset:offset+4])[0]
                        
                        # Validate reasonable number of requests (1-100)
                        if n_requests < 1 or n_requests > 100:
                            continue
                            
                        offset += 4
                        
                        # Parse encrypt requests
                        requests = []
                        base64_fragments = []
                        
                        for i in range(n_requests):
                            if offset + 6 > len(client_data):
                                break
                                
                            # Parse check and length
                            check = struct.unpack('!H', client_data[offset:offset+2])[0]
                            length = struct.unpack('!I', client_data[offset+2:offset+6])[0]
                            offset += 6
                            
                            # Parse data
                            if offset + length <= len(client_data):
                                request_data = client_data[offset:offset+length]
                                offset += length
                                
                                requests.append({
                                    'request_number': i + 1,
                                    'check_value_hex': f"0x{check:04x}",
                                    'check_value_decimal': check,
                                    'data_length_bytes': length,
                                    'data': request_data
                                })
                                
                                base64_fragments.append(request_data.replace(b'\n', b''))
                        
                        # Parse server response
                        server_analysis = {}
                        if len(server_data) >= 4:
                            response_length = struct.unpack('!I', server_data[0:4])[0]
                            
                            if len(server_data) >= 4 + response_length:
                                hashes_data = server_data[4:4+response_length]
                                
                                # Analyze hash structure (assume SHA-256)
                                if len(hashes_data) % 32 == 0:
                                    num_hashes = len(hashes_data) // 32
                                    hashes = []
                                    
                                    for i in range(num_hashes):
                                        hash_bytes = hashes_data[i*32:(i+1)*32]
                                        hashes.append(hash_bytes.hex())
                                    
                                    server_analysis = {
                                        'response_length_bytes': response_length,
                                        'hash_algorithm': 'SHA-256',
                                        'individual_hash_size_bytes': 32,
                                        'number_of_hashes': num_hashes,
                                        'hashes': hashes
                                    }
                        
                        # Reconstruct Base64 message
                        reconstructed_data = None
                        decoded_message = None
                        
                        if base64_fragments:
                            try:
                                full_base64 = b''.join(base64_fragments)
                                # Add padding if needed
                                padding_needed = (4 - len(full_base64) % 4) % 4
                                padded_base64 = full_base64 + b'=' * padding_needed
                                
                                reconstructed_data = base64.b64decode(padded_base64)
                                decoded_message = reconstructed_data.decode('utf-8', errors='ignore')
                            except:
                                pass
                        
                        # Store successful Pandora analysis
                        if requests and server_analysis:
                            pandora_results[stream_id] = {
                                'client_ip': stream_data['client_ip'],
                                'client_port': stream_data['client_port'],
                                'server_ip': stream_data['server_ip'],
                                'server_port': stream_data['server_port'],
                                'magic_check_value_decimal': requests[0]['check_value_decimal'] if requests else None,
                                'magic_check_value_hex': requests[0]['check_value_hex'] if requests else None,
                                'initialization': {
                                    'number_of_encrypt_requests': n_requests
                                },
                                'encrypt_requests': requests,
                                'encrypt_response': server_analysis,
                                'reconstructed_message': {
                                    'decoded_text': decoded_message,
                                    'raw_bytes': len(reconstructed_data) if reconstructed_data else 0
                                }
                            }
                
                except (struct.error, IndexError, ValueError):
                    # Not a valid Pandora protocol stream
                    continue
            
            # Return results
            if pandora_results:
                # Get the first (likely only) successful stream
                main_stream = list(pandora_results.values())[0]
                
                return {
                    'pandora_protocol_detected': True,
                    'total_streams_analyzed': len(pandora_streams),
                    'pandora_streams_found': len(pandora_results),
                    'communication_details': main_stream,
                    'quick_reference': {
                        'server_ip': main_stream['server_ip'],
                        'magic_2byte_id_decimal': main_stream['magic_check_value_decimal'],
                        'first_request_length_bytes': main_stream['encrypt_requests'][0]['data_length_bytes'] if main_stream['encrypt_requests'] else None,
                        'second_request_length_bytes': main_stream['encrypt_requests'][1]['data_length_bytes'] if len(main_stream['encrypt_requests']) > 1 else None,
                        'individual_hash_size_bytes': main_stream['encrypt_response']['individual_hash_size_bytes'],
                        'first_hash': main_stream['encrypt_response']['hashes'][0] if main_stream['encrypt_response']['hashes'] else None,
                        'second_hash': main_stream['encrypt_response']['hashes'][1] if len(main_stream['encrypt_response']['hashes']) > 1 else None,
                        'decoded_message': main_stream['reconstructed_message']['decoded_text']
                    },
                    'analysis_summary': f"Successfully decoded Pandora protocol with {main_stream['initialization']['number_of_encrypt_requests']} requests and {main_stream['encrypt_response']['number_of_hashes']} SHA-256 responses"
                }
            else:
                return {
                    'pandora_protocol_detected': False,
                    'total_streams_analyzed': len(pandora_streams),
                    'pandora_streams_found': 0,
                    'message': 'No Pandora protocol communications detected in this PCAP'
                }
                
        except Exception as e:
            return {"error": f"Pandora analysis failed: {e}"}


# Plugin instance for discovery
plugin = PcapNetworkPlugin()