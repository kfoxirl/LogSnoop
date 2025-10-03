#!/usr/bin/env python3
"""
Test FTP Downloads Table functionality
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logsnoop.plugins.pcap_network import PcapNetworkPlugin

def test_downloads_table():
    """Test the FTP downloads table functionality."""
    
    print("🎯 Testing FTP Downloads Table Functionality")
    print("=" * 60)
    
    plugin = PcapNetworkPlugin()
    result = plugin.parse_binary_file('test_data/FTP.pcap')
    entries = result['entries']
    
    # Test the new downloads table query
    downloads_table = plugin.query('ftp_downloads_table', entries)
    
    print("📊 FTP Downloads Table:")
    print(downloads_table.get('table_format', 'No table data'))
    print()
    
    print("📈 Summary Statistics:")
    for key, value in downloads_table.items():
        if key not in ['table_format', 'table_data']:
            print(f"   {key}: {value}")

if __name__ == "__main__":
    test_downloads_table()