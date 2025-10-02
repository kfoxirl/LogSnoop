"""
PCAP Network Traffic Plugin for LogSnoop
Parses network packet capture files (.pcap, .pcapng) using Scapy
"""

import os
import sys
from typing import Dict, List, Any, Union
from collections import Counter, defaultdict
from datetime import datetime

# Import base plugin
from .base import BaseLogPlugin

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    # Create dummy classes for development
    class rdpcap:
        pass
    class IP:
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
            "ftp_analysis", "ftp_transfers", "ftp_file_sizes", "ftp_sessions", "ftp_commands"
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
            if hasattr(http_req, 'User_Agent') and http_req.User_Agent:
                entry["http_user_agent"] = http_req.User_Agent.decode()
            entry["event_type"] = "http_request"
        
        if packet.haslayer(HTTPResponse):
            http_resp = packet[HTTPResponse]
            if hasattr(http_resp, 'Status_Code') and http_resp.Status_Code:
                entry["status"] = http_resp.Status_Code.decode()
            entry["event_type"] = "http_response"
        
        # Extract DNS information
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
            
            # Check if this is FTP traffic (port 21 = control, high ports = data)
            if dest_port == 21 or source_port == 21:
                # FTP Control Channel
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('ascii', errors='ignore').strip()
                        entry = self._parse_ftp_control(entry, payload, dest_port == 21)
                    except:
                        pass
                        
            elif packet.haslayer(Raw) and len(packet[Raw].load) > 0:
                # Potential FTP Data Channel (high port with data)
                if (dest_port > 1024 or source_port > 1024) and entry["payload_size"] > 100:
                    entry["event_type"] = "ftp_data_transfer"
                    entry["ftp_data_port"] = dest_port if dest_port > 1024 else source_port
        
        # Calculate payload size
        if packet.haslayer(Raw):
            entry["payload_size"] = len(packet[Raw].load)
        
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
        
        uploads = []
        downloads = []
        
        # Process transfer commands and try to match with data/completion
        for cmd in transfer_commands:
            transfer_info = {
                "filename": cmd.get("ftp_filename", "unknown"),
                "timestamp": cmd.get("timestamp", ""),
                "source_ip": cmd.get("source_ip", ""),
                "destination_ip": cmd.get("destination_ip", ""),
                "transfer_type": cmd.get("ftp_transfer_type", ""),
                "bytes_transferred": 0
            }
            
            # Try to find corresponding completion message with byte count
            cmd_time = cmd.get("timestamp", "")
            for completion in completions:
                if (completion.get("source_ip") == cmd.get("destination_ip") and 
                    completion.get("timestamp", "") > cmd_time):
                    transfer_info["bytes_transferred"] = completion.get("bytes_transferred", 0)
                    break
            
            if transfer_info["transfer_type"] == "upload":
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
            "completion_messages": len(completions)
        }
    
    def _query_ftp_file_sizes(self, entries: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Analyze FTP file sizes from SIZE commands and transfer completions."""
        # Get SIZE command responses (213 response code)
        size_responses = [e for e in entries if e.get("event_type") == "ftp_size_response"]
        
        # Get transfer completion messages with byte counts
        completions = [e for e in entries if (e.get("event_type") == "ftp_transfer_complete" and 
                                             e.get("bytes_transferred", 0) > 0)]
        
        file_sizes = {}
        transfer_sizes = []
        
        # Process SIZE responses
        for entry in size_responses:
            # Need to correlate with previous SIZE command to get filename
            size = entry.get("bytes_transferred", 0)
            if size > 0:
                transfer_sizes.append(size)
        
        # Process completion messages
        for entry in completions:
            size = entry.get("bytes_transferred", 0)
            if size > 0:
                transfer_sizes.append(size)
        
        if not transfer_sizes:
            return {
                "message": "No file size information found in FTP traffic",
                "size_responses": len(size_responses),
                "completion_messages": len(completions)
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
            "size_responses_found": len(size_responses),
            "completion_messages_found": len(completions)
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


# Plugin instance for discovery
plugin = PcapNetworkPlugin()