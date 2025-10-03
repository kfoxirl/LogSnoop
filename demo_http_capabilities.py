#!/usr/bin/env python3
"""
Comprehensive HTTP Analysis Demonstration
Shows all available HTTP analysis queries and their capabilities
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logsnoop.plugins.pcap_network import PcapNetworkPlugin

def demonstrate_http_capabilities():
    """Demonstrate all HTTP analysis capabilities."""
    
    print("🌐 LogSnoop HTTP Traffic Analysis - Complete Feature Demonstration")
    print("=" * 90)
    
    plugin = PcapNetworkPlugin()
    
    # Load the HTTP2.pcap file
    test_file = 'test_data/HTTP2.pcap'
    
    print(f"📄 Loading PCAP file: {test_file}")
    result = plugin.parse_binary_file(test_file)
    entries = result['entries']
    print(f"📊 Loaded {len(entries)} packet entries")
    
    print(f"\n🎯 Available HTTP Analysis Queries:")
    print("=" * 90)
    
    # Get all HTTP queries from supported queries
    all_queries = plugin.supported_queries
    http_queries = [q for q in all_queries if q.startswith('http_')]
    
    query_descriptions = {
        'http_analysis': 'Comprehensive HTTP traffic overview with statistics',
        'http_transactions': 'Request/response transaction matching and analysis', 
        'http_status_codes': 'HTTP status code patterns and error analysis',
        'http_methods': 'HTTP method usage and security implications',
        'http_user_agents': 'User-Agent analysis for browser and bot detection',
        'http_hosts': 'Host header analysis and domain mapping',
        'http_content_types': 'Content-Type patterns and file type analysis',
        'http_errors': 'HTTP error pattern analysis and troubleshooting',
        'http_performance': 'HTTP performance metrics and bandwidth analysis',
        'http_security': 'Security threat detection and vulnerability analysis',
        'http_file_downloads': 'File download detection and forensic analysis'
    }
    
    for i, query in enumerate(http_queries, 1):
        description = query_descriptions.get(query, "Advanced HTTP traffic analysis")
        print(f"{i:2d}. {query:20s} - {description}")
    
    print(f"\n🚀 Running Full HTTP Analysis Suite:")
    print("=" * 90)
    
    # Run a comprehensive analysis
    for query in http_queries:
        print(f"\n--- 📊 {query.upper().replace('_', ' ')} ---")
        try:
            result = plugin.query(query, entries)
            
            # Extract and display key insights
            if query == 'http_analysis':
                print(f"✓ HTTP Traffic Summary: {result.get('total_http_requests', 0)} requests, {result.get('total_http_responses', 0)} responses")
                print(f"✓ Data Transfer: {result.get('total_content_mb', 0)} MB total content")
                print(f"✓ Protocol Efficiency: {result.get('request_response_ratio', 0)} req/resp ratio")
                
            elif query == 'http_transactions':
                completed = result.get('completed_transactions', 0)
                total = result.get('total_transactions', 0)
                success_rate = (completed / max(total, 1)) * 100
                print(f"✓ Transaction Success Rate: {success_rate:.1f}% ({completed}/{total})")
                
            elif query == 'http_status_codes':
                errors = result.get('error_responses', 0)
                total = result.get('total_responses', 0)
                error_rate = (errors / max(total, 1)) * 100
                print(f"✓ HTTP Error Rate: {error_rate:.1f}% ({errors}/{total} responses)")
                
            elif query == 'http_methods':
                unsafe = len(result.get('unsafe_methods', {}))
                print(f"✓ HTTP Method Security: {unsafe} potentially unsafe methods detected")
                
            elif query == 'http_user_agents':
                bots = len(result.get('automation_tools', {}))
                browsers = len(result.get('browser_breakdown', {}))
                print(f"✓ User-Agent Analysis: {browsers} browser types, {bots} automation tools detected")
                
            elif query == 'http_hosts':
                hosts = result.get('unique_hosts', 0)
                domains = len(result.get('potential_domains', []))
                print(f"✓ Host Analysis: {hosts} unique hosts, {domains} domain names identified")
                
            elif query == 'http_content_types':
                types = result.get('unique_content_types', 0)
                print(f"✓ Content Diversity: {types} different content types detected")
                
            elif query == 'http_errors':
                error_rate = result.get('error_rate', 0)
                print(f"✓ Error Analysis: {error_rate}% error rate in HTTP traffic")
                
            elif query == 'http_performance':
                mb_total = result.get('total_content_mb', 0)
                avg_size = result.get('avg_response_size', 0)
                print(f"✓ Performance Metrics: {mb_total} MB transferred, {avg_size:,} bytes avg response")
                
            elif query == 'http_security':
                score = result.get('security_score', 0)
                threats = result.get('suspicious_requests', 0)
                print(f"✓ Security Assessment: {score}/100 security score, {threats} potential threats")
                
            elif query == 'http_file_downloads':
                downloads = result.get('total_downloads', 0)
                mb_downloaded = result.get('total_download_mb', 0)
                print(f"✓ File Download Analysis: {downloads} files downloaded, {mb_downloaded} MB total")
            
            print(f"  Status: ✅ Analysis completed successfully")
                
        except Exception as e:
            print(f"  Status: ❌ Error: {e}")
    
    print(f"\n🎉 HTTP Analysis Capabilities Summary:")
    print("=" * 90)
    print("✅ Network Forensics: Complete HTTP request/response correlation")
    print("✅ Security Analysis: Threat detection and vulnerability assessment") 
    print("✅ Performance Monitoring: Bandwidth usage and response time analysis")
    print("✅ User Behavior: User-Agent analysis and client identification")
    print("✅ Content Analysis: File downloads and content type classification")
    print("✅ Error Diagnosis: HTTP error pattern analysis and troubleshooting")
    print("✅ Protocol Compliance: HTTP method usage and status code validation")
    print("✅ Traffic Intelligence: Host mapping and domain identification")
    
    print(f"\n💼 Use Cases:")
    print("  🔍 Digital Forensics: Investigate suspicious HTTP activity")
    print("  🛡️  Security Monitoring: Detect web-based attacks and intrusions")  
    print("  📊 Performance Analysis: Optimize web application performance")
    print("  🕵️  Incident Response: Analyze HTTP traffic during security incidents")
    print("  📈 Compliance Auditing: Monitor HTTP protocol compliance")
    print("  🤖 Bot Detection: Identify automated tools and web scrapers")
    
    print(f"\n🏆 LogSnoop HTTP Analysis: Enterprise-Grade Network Intelligence")

if __name__ == "__main__":
    demonstrate_http_capabilities()