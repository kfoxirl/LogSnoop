#!/usr/bin/env python3
"""
Test HTTP Traffic Analysis with real HTTP2.pcap file
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logsnoop.plugins.pcap_network import PcapNetworkPlugin

def test_http2_analysis():
    """Test the HTTP analysis functionality with HTTP2.pcap."""
    
    print("🌐 Testing HTTP Traffic Analysis with HTTP2.pcap")
    print("=" * 80)
    
    plugin = PcapNetworkPlugin()
    
    # Load the HTTP2.pcap file
    test_file = 'test_data/HTTP2.pcap'
    
    if not os.path.exists(test_file):
        print(f"❌ Test file {test_file} not found.")
        return
    
    print(f"📄 Loading PCAP file: {test_file}")
    result = plugin.parse_binary_file(test_file)
    entries = result['entries']
    print(f"📊 Loaded {len(entries)} packet entries")
    
    # Check what types of traffic we have
    event_types = {}
    for entry in entries:
        event_type = entry.get('event_type', 'unknown')
        event_types[event_type] = event_types.get(event_type, 0) + 1
    
    print(f"\n📈 Traffic Breakdown:")
    for event_type, count in sorted(event_types.items()):
        print(f"  {event_type}: {count}")
    
    # Test key HTTP Analysis queries with the real data
    key_queries = [
        'http_analysis',
        'http_transactions', 
        'http_status_codes',
        'http_methods',
        'http_user_agents',
        'http_hosts',
        'http_security',
        'http_file_downloads'
    ]
    
    print(f"\n🔍 Testing {len(key_queries)} key HTTP analysis queries:")
    print("=" * 80)
    
    for query_name in key_queries:
        print(f"\n--- 🎯 {query_name.upper().replace('_', ' ')} ---")
        try:
            result = plugin.query(query_name, entries)
            
            if isinstance(result, dict):
                # Show the most relevant information for each query type
                if query_name == 'http_analysis':
                    print(f"  📊 Total HTTP Requests: {result.get('total_http_requests', 0)}")
                    print(f"  📊 Total HTTP Responses: {result.get('total_http_responses', 0)}")
                    print(f"  🔄 Request/Response Ratio: {result.get('request_response_ratio', 0)}")
                    print(f"  📈 Content Transfer: {result.get('total_content_mb', 0)} MB")
                    if result.get('top_methods'):
                        print(f"  🛠️  Top Methods: {result['top_methods']}")
                    if result.get('top_status_codes'):
                        print(f"  📋 Top Status Codes: {result['top_status_codes']}")
                
                elif query_name == 'http_transactions':
                    print(f"  🔗 Total Transactions: {result.get('total_transactions', 0)}")
                    print(f"  ✅ Completed: {result.get('completed_transactions', 0)}")
                    print(f"  ❌ Incomplete: {result.get('incomplete_transactions', 0)}")
                    if result.get('transactions') and len(result['transactions']) > 0:
                        print(f"  📋 Sample Transaction:")
                        tx = result['transactions'][0]
                        print(f"    Method: {tx.get('method', 'N/A')}")
                        print(f"    URL: {tx.get('url', 'N/A')}")
                        print(f"    Host: {tx.get('host', 'N/A')}")
                        print(f"    Status: {tx.get('status_code', 'N/A')}")
                
                elif query_name == 'http_status_codes':
                    print(f"  📊 Total Responses: {result.get('total_responses', 0)}")
                    print(f"  ✅ Success (2xx): {result.get('success_responses', 0)}")
                    print(f"  ❌ Errors (4xx+5xx): {result.get('error_responses', 0)}")
                    if result.get('status_categories'):
                        print(f"  📋 Status Categories: {result['status_categories']}")
                
                elif query_name == 'http_methods':
                    print(f"  📊 Total Requests: {result.get('total_requests', 0)}")
                    if result.get('method_breakdown'):
                        print(f"  🛠️  Method Breakdown: {result['method_breakdown']}")
                    if result.get('unsafe_methods'):
                        print(f"  ⚠️  Unsafe Methods: {result['unsafe_methods']}")
                
                elif query_name == 'http_user_agents':
                    print(f"  👥 Requests with User-Agent: {result.get('total_requests_with_ua', 0)}")
                    print(f"  🔢 Unique User-Agents: {result.get('unique_user_agents', 0)}")
                    if result.get('browser_breakdown'):
                        print(f"  🌐 Browser Breakdown: {result['browser_breakdown']}")
                    if result.get('automation_tools'):
                        print(f"  🤖 Automation Tools: {result['automation_tools']}")
                
                elif query_name == 'http_hosts':
                    print(f"  📊 Total Requests: {result.get('total_requests', 0)}")
                    print(f"  🏠 Unique Hosts: {result.get('unique_hosts', 0)}")
                    if result.get('top_hosts'):
                        print(f"  🔝 Top Hosts: {dict(list(result['top_hosts'].items())[:5])}")
                
                elif query_name == 'http_security':
                    print(f"  🔒 Security Score: {result.get('security_score', 0)}/100")
                    print(f"  🚨 Suspicious Requests: {result.get('suspicious_requests', 0)}")
                    print(f"  🔐 Auth Failures (401): {result.get('authentication_failures_401', 0)}")
                    print(f"  🚫 Forbidden (403): {result.get('forbidden_access_403', 0)}")
                    if result.get('dangerous_methods'):
                        print(f"  ⚠️  Dangerous Methods: {result['dangerous_methods']}")
                
                elif query_name == 'http_file_downloads':
                    print(f"  📥 Total Downloads: {result.get('total_downloads', 0)}")
                    print(f"  📊 Download Size: {result.get('total_download_mb', 0)} MB")
                    if result.get('downloads_by_type'):
                        print(f"  📁 Download Types: {result['downloads_by_type']}")
                    print(f"  ✅ Successful: {result.get('successful_downloads', 0)}")
                    print(f"  ❌ Failed: {result.get('failed_downloads', 0)}")
                
                # Always show analysis summary
                if 'analysis' in result:
                    print(f"  💡 {result['analysis']}")
                elif 'analysis_summary' in result:
                    print(f"  💡 {result['analysis_summary']}")
                elif 'summary' in result:
                    print(f"  💡 {result['summary']}")
                    
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    print(f"\n{'='*80}")
    print("🎉 HTTP Analysis Testing Complete!")
    print("✨ Comprehensive HTTP traffic analysis capabilities demonstrated.")

if __name__ == "__main__":
    test_http2_analysis()