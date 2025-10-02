#!/usr/bin/env python3
"""
Test script to demonstrate FTP PCAP analysis functionality
Creates mock FTP packet data and tests all FTP query methods
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logsnoop.plugins.pcap_network import PcapNetworkPlugin

def create_mock_ftp_data():
    """Create mock FTP packet data for testing."""
    return [
        # FTP Control channel - USER command
        {
            "timestamp": "2024-01-15 10:00:01",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.200", 
            "source_port": 45231,
            "destination_port": 21,
            "protocol": "TCP",
            "packet_size": 64,
            "event_type": "ftp_command",
            "ftp_command": "USER",
            "ftp_filename": "",
            "ftp_transfer_type": ""
        },
        # FTP Control channel - PASS command
        {
            "timestamp": "2024-01-15 10:00:02",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.200",
            "source_port": 45231,
            "destination_port": 21,
            "protocol": "TCP", 
            "packet_size": 72,
            "event_type": "ftp_command",
            "ftp_command": "PASS",
            "ftp_filename": "",
            "ftp_transfer_type": ""
        },
        # FTP Control - STOR command (upload)
        {
            "timestamp": "2024-01-15 10:00:10",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.200",
            "source_port": 45231,
            "destination_port": 21,
            "protocol": "TCP",
            "packet_size": 85,
            "event_type": "ftp_command",
            "ftp_command": "STOR",
            "ftp_filename": "upload_file.txt",
            "ftp_transfer_type": "upload"
        },
        # FTP Data transfer for upload
        {
            "timestamp": "2024-01-15 10:00:11",
            "source_ip": "192.168.1.100", 
            "destination_ip": "192.168.1.200",
            "source_port": 45232,
            "destination_port": 20,
            "protocol": "TCP",
            "packet_size": 1024,
            "event_type": "ftp_data_transfer",
            "bytes_transferred": 5120,
            "ftp_filename": "upload_file.txt"
        },
        # FTP Transfer completion
        {
            "timestamp": "2024-01-15 10:00:12",
            "source_ip": "192.168.1.200",
            "destination_ip": "192.168.1.100", 
            "source_port": 21,
            "destination_port": 45231,
            "protocol": "TCP",
            "packet_size": 96,
            "event_type": "ftp_transfer_complete",
            "bytes_transferred": 5120,
            "ftp_response": "226"
        },
        # FTP Control - RETR command (download)  
        {
            "timestamp": "2024-01-15 10:01:00",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.200",
            "source_port": 45231,
            "destination_port": 21,
            "protocol": "TCP",
            "packet_size": 88,
            "event_type": "ftp_command",
            "ftp_command": "RETR",
            "ftp_filename": "download_file.pdf", 
            "ftp_transfer_type": "download"
        },
        # FTP SIZE response
        {
            "timestamp": "2024-01-15 10:01:01",
            "source_ip": "192.168.1.200",
            "destination_ip": "192.168.1.100",
            "source_port": 21,
            "destination_port": 45231,
            "protocol": "TCP",
            "packet_size": 72,
            "event_type": "ftp_size_response",
            "bytes_transferred": 102400,
            "ftp_response": "213"
        },
        # FTP Data transfer for download
        {
            "timestamp": "2024-01-15 10:01:02",
            "source_ip": "192.168.1.200",
            "destination_ip": "192.168.1.100",
            "source_port": 20,
            "destination_port": 45233,
            "protocol": "TCP", 
            "packet_size": 1500,
            "event_type": "ftp_data_transfer",
            "bytes_transferred": 102400,
            "ftp_filename": "download_file.pdf"
        },
        # FTP Transfer completion for download
        {
            "timestamp": "2024-01-15 10:01:05",
            "source_ip": "192.168.1.200", 
            "destination_ip": "192.168.1.100",
            "source_port": 21,
            "destination_port": 45231,
            "protocol": "TCP",
            "packet_size": 98,
            "event_type": "ftp_transfer_complete",
            "bytes_transferred": 102400,
            "ftp_response": "226"
        },
        # FTP LIST command
        {
            "timestamp": "2024-01-15 10:02:00",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.200",
            "source_port": 45231,
            "destination_port": 21,
            "protocol": "TCP",
            "packet_size": 68,
            "event_type": "ftp_command",
            "ftp_command": "LIST",
            "ftp_filename": "",
            "ftp_transfer_type": ""
        }
    ]

def test_ftp_queries():
    """Test all FTP query methods with mock data."""
    plugin = PcapNetworkPlugin()
    mock_data = create_mock_ftp_data()
    
    print("=== Testing FTP Analysis Functionality ===\n")
    
    # Test FTP Analysis
    print("1. FTP Analysis Overview:")
    result = plugin._query_ftp_analysis(mock_data)
    for key, value in result.items():
        print(f"   {key}: {value}")
    print()
    
    # Test FTP Transfers 
    print("2. FTP File Transfers:")
    result = plugin._query_ftp_transfers(mock_data)
    for key, value in result.items():
        if isinstance(value, list) and len(value) > 0:
            print(f"   {key}: {len(value)} items")
            for item in value[:2]:  # Show first 2
                print(f"      - {item}")
        else:
            print(f"   {key}: {value}")
    print()
    
    # Test FTP File Sizes
    print("3. FTP File Size Analysis:")
    result = plugin._query_ftp_file_sizes(mock_data)
    for key, value in result.items():
        print(f"   {key}: {value}")
    print()
    
    # Test FTP Sessions
    print("4. FTP Session Analysis:")
    result = plugin._query_ftp_sessions(mock_data)
    for key, value in result.items():
        if isinstance(value, dict) and key == "sessions":
            print(f"   {key}: {len(value)} sessions")
            for session_id, session_data in value.items():
                print(f"      {session_id}: {session_data}")
        else:
            print(f"   {key}: {value}")
    print()
    
    # Test FTP Commands
    print("5. FTP Command Analysis:")
    result = plugin._query_ftp_commands(mock_data)
    for key, value in result.items():
        if isinstance(value, dict) and key == "command_breakdown":
            print(f"   {key}:")
            for cmd, cmd_data in value.items():
                print(f"      {cmd}: {cmd_data['count']} times - {cmd_data['explanation']}")
        else:
            print(f"   {key}: {value}")
    print()

if __name__ == "__main__":
    test_ftp_queries()