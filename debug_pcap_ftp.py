#!/usr/bin/env python3
"""
PCAP FTP Analysis Debugging Script
Helps diagnose issues with FTP file size detection
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logsnoop.plugins.pcap_network import PcapNetworkPlugin

def analyze_pcap_file(pcap_path):
    """Analyze a PCAP file and show detailed FTP parsing information."""
    
    if not os.path.exists(pcap_path):
        print(f"❌ PCAP file not found: {pcap_path}")
        return
    
    print(f"🔍 Analyzing PCAP file: {pcap_path}")
    print("="*60)
    
    try:
        plugin = PcapNetworkPlugin()
        
        # Parse the PCAP file
        result = plugin.parse_binary_file(pcap_path)
        entries = result["entries"]
        summary = result["summary"]
        
        print(f"\n📊 Basic PCAP Statistics:")
        print(f"   Total packets: {len(entries)}")
        print(f"   Total bytes: {summary.get('total_bytes', 0):,}")
        print(f"   Unique IPs: {summary.get('unique_ips', 0)}")
        print(f"   Protocols: {summary.get('protocols', {})}")
        
        # Filter FTP-related entries
        ftp_entries = []
        for entry in entries:
            event_type = entry.get("event_type", "")
            dest_port = entry.get("destination_port", 0)
            src_port = entry.get("source_port", 0)
            
            # Check for FTP traffic (port 21, or FTP event types)
            if (dest_port == 21 or src_port == 21 or 
                "ftp" in event_type or
                (dest_port > 1024 and src_port > 1024 and entry.get("payload_size", 0) > 100)):
                ftp_entries.append(entry)
        
        print(f"\n🔍 FTP Traffic Analysis:")
        print(f"   FTP-related packets: {len(ftp_entries)}")
        
        if ftp_entries:
            print(f"\n📝 FTP Packet Details:")
            for i, entry in enumerate(ftp_entries[:10]):  # Show first 10
                print(f"   {i+1:2}. {entry.get('timestamp', 'N/A')}")
                print(f"       {entry.get('source_ip')}:{entry.get('source_port')} -> {entry.get('destination_ip')}:{entry.get('destination_port')}")
                print(f"       Type: {entry.get('event_type')} | Size: {entry.get('packet_size', 0)} bytes")
                if entry.get("ftp_command"):
                    print(f"       FTP Command: {entry.get('ftp_command')} {entry.get('ftp_filename', '')}")
                if entry.get("ftp_response"):
                    print(f"       FTP Response: {entry.get('ftp_response')}")
                if entry.get("bytes_transferred", 0) > 0:
                    print(f"       Bytes Transferred: {entry.get('bytes_transferred'):,}")
                print()
        
        # Run FTP-specific queries
        print(f"\n🎯 FTP Analysis Results:")
        
        # FTP Analysis Overview
        ftp_analysis = plugin.query("ftp_analysis", entries)
        print(f"\n1. FTP Analysis Overview:")
        for key, value in ftp_analysis.items():
            print(f"   {key}: {value}")
        
        # FTP Transfers
        ftp_transfers = plugin.query("ftp_transfers", entries)
        print(f"\n2. FTP File Transfers:")
        for key, value in ftp_transfers.items():
            if isinstance(value, list) and len(value) > 0:
                print(f"   {key}: {len(value)} items")
                for item in value:
                    print(f"      - {item}")
            else:
                print(f"   {key}: {value}")
        
        # FTP File Sizes
        ftp_sizes = plugin.query("ftp_file_sizes", entries)
        print(f"\n3. FTP File Size Analysis:")
        for key, value in ftp_sizes.items():
            print(f"   {key}: {value}")
        
        # Debug: Look for specific patterns that might indicate the 87-byte issue
        print(f"\n🐛 Debug Information:")
        
        # Check for SIZE responses
        size_responses = [e for e in entries if e.get("event_type") == "ftp_size_response"]
        print(f"   SIZE responses found: {len(size_responses)}")
        for resp in size_responses:
            print(f"      - {resp.get('timestamp')}: {resp.get('bytes_transferred')} bytes")
        
        # Check for transfer completions
        completions = [e for e in entries if e.get("event_type") == "ftp_transfer_complete"]
        print(f"   Transfer completions found: {len(completions)}")
        for comp in completions:
            print(f"      - {comp.get('timestamp')}: {comp.get('bytes_transferred')} bytes")
        
        # Check for data transfers
        data_transfers = [e for e in entries if e.get("event_type") == "ftp_data_transfer"]
        print(f"   Data transfer packets found: {len(data_transfers)}")
        for dt in data_transfers:
            print(f"      - {dt.get('timestamp')}: {dt.get('bytes_transferred', dt.get('packet_size', 0))} bytes")
        
        # Look for packets with payload > 87 bytes
        large_packets = [e for e in entries if e.get("packet_size", 0) > 87]
        print(f"   Packets larger than 87 bytes: {len(large_packets)}")
        
        if len(large_packets) > 0:
            print(f"   Largest packet: {max(e.get('packet_size', 0) for e in large_packets)} bytes")
        
    except Exception as e:
        print(f"❌ Error analyzing PCAP: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Main function to run PCAP analysis."""
    if len(sys.argv) != 2:
        print("Usage: python debug_pcap_ftp.py <pcap_file>")
        print("\nExample:")
        print("  python debug_pcap_ftp.py capture.pcap")
        print("  python debug_pcap_ftp.py ftp_session.pcapng")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap_file(pcap_file)

if __name__ == "__main__":
    main()