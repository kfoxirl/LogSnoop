#!/usr/bin/env python3
"""
Demo script showing comprehensive Telnet traffic analysis capabilities.

This script demonstrates all 6 Telnet analysis queries:
- telnet_analysis: Overall tr                    # Show extracted system information
                    system_info = result.get('system_information', {})
                    if system_info and any(v for v in system_info.values() if v):
                        print(f"\n🖥️  SYSTEM INFORMATION EXTRACTED:")
                        if system_info.get('hostname'):
                            print(f"   🏠 Hostname: {system_info['hostname']}")
                        if system_info.get('operating_system'):
                            print(f"   💿 OS: {system_info['operating_system']} {system_info.get('kernel_version', '')}")
                        if system_info.get('cpu_architecture'):
                            print(f"   🔧 CPU: {system_info['cpu_architecture']}")
                        if system_info.get('architecture_description'):
                            print(f"   📋 Architecture: {system_info['architecture_description']}")
                        if system_info.get('build_info'):
                            print(f"   🏗️  Build: {system_info['build_info']}")
                    
                    # Show security analysis
                    security = result.get('security_analysis', {})
                    if any(security.values()):
                        print(f"\n🔍 Security Analysis:")
                        if security.get('system_info_commands', 0) > 0:
                            print(f"   🖥️  System information queries: {security['system_info_commands']}")
                        if security.get('privileged_commands', 0) > 0:
                            print(f"   👑 Privileged operations: {security['privileged_commands']}")
                        if security.get('session_management', 0) > 0:
                            print(f"   🚪 Session management: {security['session_management']}")
                    
                    analysis_note = result.get('analysis_note', '')
                    if analysis_note:
                        print(f"\n📝 Analysis: {analysis_note}")
- telnet_sessions: Detailed session reconstruction  
- telnet_authentication: Authentication event analysis
- telnet_commands: Command extraction and analysis
- telnet_traffic: Traffic pattern analysis
- telnet_security: Security assessment and recommendations
"""

import os
import sys
from pathlib import Path

# Add the logsnoop module to the path
sys.path.insert(0, str(Path(__file__).parent))

from logsnoop.core import LogParser

def main():
    """Run comprehensive Telnet analysis demo."""
    
    print("=" * 70)
    print("TELNET TRAFFIC ANALYSIS DEMO")
    print("=" * 70)
    print()
    
    # Initialize parser
    parser = LogParser()
    
    # Parse the Telnet PCAP file
    pcap_file = "test_data/Telnet.pcap"
    
    if not os.path.exists(pcap_file):
        print(f"❌ Error: {pcap_file} not found!")
        print("Please ensure the Telnet.pcap file is in the test_data/ directory")
        return
    
    print(f"📁 Parsing PCAP file: {pcap_file}")
    
    try:
        result = parser.parse_log_file(pcap_file, "pcap_network")
        file_id = result['file_id']
        print(f"✅ Successfully parsed file (ID: {file_id})")
        if result.get('duplicate'):
            print("ℹ️  Note: File was previously parsed (using cached data)")
        print()
    except Exception as e:
        print(f"❌ Error parsing file: {e}")
        return
    
    # Analysis functions with descriptions
    analyses = [
        ("telnet_analysis", "📊 Overall Telnet Traffic Summary", 
         "Provides high-level statistics about Telnet sessions, packets, and data transfer"),
        
        ("telnet_authentication", "🔐 Authentication Analysis",
         "Analyzes login attempts, captures usernames, and tracks authentication flows"),
        
        ("telnet_sessions", "💬 Session Reconstruction", 
         "Reconstructs detailed session conversations and data exchanges"),
        
        ("telnet_commands", "⌨️  Command Analysis",
         "Extracts and categorizes commands executed during Telnet sessions"),
        
        ("telnet_traffic", "📈 Traffic Pattern Analysis",
         "Analyzes packet flow, timing, and communication patterns"),
        
        ("telnet_security", "🛡️  Security Assessment", 
         "Evaluates security risks and provides recommendations")
    ]
    
    # Run each analysis
    for query_type, title, description in analyses:
        print(f"{title}")
        print(f"Description: {description}")
        print("-" * 50)
        
        try:
            result = parser.query_logs("pcap_network", query_type, file_id=file_id, file_path=pcap_file)
            
            if "error" in result:
                print(f"❌ Error: {result['error']}")
            else:
                # Pretty print key results
                if query_type == "telnet_analysis":
                    print(f"📦 Total Packets: {result.get('total_telnet_packets', 0)}")
                    print(f"🔗 Sessions: {result.get('total_sessions', 0)}")
                    print(f"📊 Total Bytes: {result.get('total_bytes', 0):,}")
                    print(f"👥 Unique Clients: {result.get('unique_clients', 0)}")
                    print(f"🖥️  Servers: {result.get('unique_servers', 0)}")
                    
                    # Show target system information if available
                    system_info = result.get('system_information', {})
                    if system_info and system_info.get('hostname'):
                        print(f"\n🎯 TARGET SYSTEM IDENTIFIED:")
                        print(f"   🏠 Hostname: {system_info['hostname']}")
                        print(f"   🔧 Architecture: {system_info.get('cpu_architecture', 'Unknown')}")
                        if system_info.get('operating_system'):
                            print(f"   💿 OS: {system_info['operating_system']} {system_info.get('kernel_version', '')}")
                    
                elif query_type == "telnet_authentication":
                    print(f"🔑 Authentication Attempts: {result.get('total_auth_attempts', 0)}")
                    print(f"✅ Successful: {result.get('successful_attempts', 0)}")
                    print(f"❌ Failed: {result.get('failed_attempts', 0)}")
                    
                    # Display captured credentials with security warning
                    credentials = result.get('captured_credentials', [])
                    if credentials:
                        print(f"\n🚨 {result.get('security_warning', 'Security Warning')}")
                        print("🔓 CAPTURED CREDENTIALS:")
                        for cred in credentials:
                            username = cred.get('username', '[Unknown]').replace('\x00', '')
                            password = cred.get('password', '[Unknown]').replace('\x00', '')
                            print(f"   👤 Username: {username}")
                            print(f"   🔑 Password: {password}")
                        print("⚠️  These credentials were transmitted in PLAINTEXT!")
                    
                    usernames = result.get('unique_usernames', [])
                    clean_usernames = [u.replace('\x00', '') for u in usernames if u.replace('\x00', '')]
                    print(f"\n👤 Captured Usernames: {', '.join(clean_usernames) if clean_usernames else 'None'}")
                    
                    passwords = result.get('unique_passwords', [])
                    clean_passwords = [p.replace('\x00', '') for p in passwords if p.replace('\x00', '')]
                    print(f"🔑 Captured Passwords: {', '.join(clean_passwords) if clean_passwords else 'None'}")
                    
                    # Show authentication sequence for first session
                    auth_events = result.get('authentication_events', [])
                    if auth_events:
                        print("\n🔍 Authentication Sequence:")
                        for event in auth_events[0].get('auth_sequence', [])[:5]:  # First 5 events
                            event_type = event.get('event', 'unknown')
                            direction = event.get('direction', '')
                            timestamp = event.get('timestamp', '')[:19]  # Remove microseconds
                            print(f"   {timestamp} [{direction}] {event_type}")
                        if len(auth_events[0].get('auth_sequence', [])) > 5:
                            print(f"   ... and {len(auth_events[0].get('auth_sequence', [])) - 5} more events")
                    
                elif query_type == "telnet_sessions":
                    print(f"🔗 Total Sessions: {result.get('total_sessions', 0)}")
                    summary = result.get('summary', {})
                    print(f"📦 Total Packets: {summary.get('total_packets', 0)}")
                    print(f"💾 Data Packets: {summary.get('total_data_packets', 0)}")
                    print(f"⏱️  Avg Duration: {summary.get('avg_session_duration', 0):.2f} seconds")
                    
                    # Show sample data exchanges
                    sessions = result.get('sessions', [])
                    if sessions:
                        exchanges = sessions[0].get('data_exchanges', [])
                        readable_exchanges = [e for e in exchanges if e.get('data', '').isprintable() and len(e.get('data', '')) > 1]
                        
                        if readable_exchanges:
                            print(f"\n💬 Sample Data Exchanges:")
                            for exchange in readable_exchanges[:3]:  # First 3 readable exchanges
                                direction = "Client→Server" if exchange.get('direction') == 'C->S' else "Server→Client"
                                data = exchange.get('data', '')[:50]  # Truncate long data
                                if len(exchange.get('data', '')) > 50:
                                    data += "..."
                                print(f"   [{direction}] {repr(data)}")
                    
                elif query_type == "telnet_commands":
                    print(f"⌨️  Total Commands: {result.get('total_commands', 0)}")
                    print(f"🆔 Unique Commands: {result.get('unique_commands', 0)}")
                    
                    # Show all commands found
                    commands = result.get('commands', [])
                    if commands:
                        print("\n💻 COMMANDS EXECUTED:")
                        for i, cmd in enumerate(commands, 1):
                            timestamp = cmd.get('timestamp', '')[:19]  # Remove microseconds
                            command = cmd.get('command', '')
                            category = cmd.get('category', 'unknown')
                            
                            # Category emoji mapping
                            category_emoji = {
                                'system_info': '🖥️',
                                'session': '🚪',
                                'directory': '📁',
                                'file_view': '📄',
                                'privilege': '👑',
                                'network': '🌐',
                                'process': '⚙️',
                                'other': '❓'
                            }
                            
                            emoji = category_emoji.get(category, '❓')
                            print(f"   {i}. {emoji} {command}")
                            print(f"      ⏰ {timestamp}")
                            print(f"      🏷️  Category: {category}")
                    
                    categories = result.get('command_categories', {})
                    if categories:
                        print(f"\n� Command Categories:")
                        for category, count in categories.items():
                            print(f"   • {category}: {count}")
                    
                    # Show security analysis
                    security = result.get('security_analysis', {})
                    if any(security.values()):
                        print(f"\n🔍 Security Analysis:")
                        if security.get('system_info_commands', 0) > 0:
                            print(f"   �️  System information queries: {security['system_info_commands']}")
                        if security.get('privileged_commands', 0) > 0:
                            print(f"   👑 Privileged operations: {security['privileged_commands']}")
                        if security.get('session_management', 0) > 0:
                            print(f"   🚪 Session management: {security['session_management']}")
                    
                    analysis_note = result.get('analysis_note', '')
                    if analysis_note:
                        print(f"\n📝 Analysis: {analysis_note}")
                    
                elif query_type == "telnet_traffic":
                    stats = result.get('traffic_statistics', {})
                    print(f"📈 Packets: {stats.get('total_packets', 0)} total")
                    print(f"   ↗️ Client→Server: {stats.get('client_to_server_packets', 0)}")
                    print(f"   ↙️ Server→Client: {stats.get('server_to_client_packets', 0)}")
                    print(f"📊 Average Packet Size: {stats.get('average_packet_size', 0):.1f} bytes")
                    print(f"⏱️  Duration: {stats.get('total_duration_seconds', 0):.2f} seconds")
                    print(f"📡 Rate: {stats.get('packets_per_second', 0):.1f} packets/sec")
                    
                elif query_type == "telnet_security":
                    print(f"🛡️  Security Score: {result.get('security_score', 0)}/100")
                    print(f"⚠️  Risk Level: {result.get('risk_level', 'Unknown')}")
                    print(f"🚨 Total Findings: {result.get('total_findings', 0)}")
                    
                    findings = result.get('security_findings', [])
                    if findings:
                        print("\n🔍 Key Security Issues:")
                        for finding in findings[:3]:  # Top 3 findings
                            severity = finding.get('severity', 'Unknown')
                            issue = finding.get('issue', 'Unknown')
                            emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
                            print(f"   {emoji} {severity}: {issue}")
                    
                    recommendations = result.get('recommendations', [])
                    if recommendations:
                        print(f"\n💡 Key Recommendations:")
                        for rec in recommendations[:2]:  # Top 2 recommendations
                            print(f"   • {rec}")
                        
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
        
        print()
        print()
    
    print("=" * 70)
    print("TELNET FORENSIC ANALYSIS SUMMARY")
    print("=" * 70)
    print()
    
    # Final summary
    try:
        # Get overall analysis
        analysis = parser.query_logs("pcap_network", "telnet_analysis", file_id=file_id, file_path=pcap_file)
        auth_analysis = parser.query_logs("pcap_network", "telnet_authentication", file_id=file_id, file_path=pcap_file)
        security_analysis = parser.query_logs("pcap_network", "telnet_security", file_id=file_id, file_path=pcap_file)
        
        print("🔍 FORENSIC FINDINGS:")
        print(f"   • Analyzed {analysis.get('total_telnet_packets', 0)} Telnet packets")
        print(f"   • Found {analysis.get('total_sessions', 0)} communication session(s)")
        print(f"   • Detected {auth_analysis.get('total_auth_attempts', 0)} authentication attempt(s)")
        
        usernames = auth_analysis.get('unique_usernames', [])
        if usernames:
            clean_usernames = [u.replace('\x00', '') for u in usernames if u.replace('\x00', '')]
            if clean_usernames:
                print(f"   • Captured username(s): {', '.join(clean_usernames)}")
        
        print(f"   • Security risk level: {security_analysis.get('risk_level', 'Unknown')}")
        print(f"   • Security score: {security_analysis.get('security_score', 0)}/100")
        
        print()
        print("⚠️  CRITICAL SECURITY ISSUES:")
        print("   • Telnet transmits ALL data in plaintext (including passwords)")
        print("   • Authentication credentials are visible to network sniffers")
        print("   • All commands and responses can be intercepted")
        
        print()
        print("🛠️  IMMEDIATE ACTIONS REQUIRED:")
        print("   1. Replace Telnet with SSH immediately")
        print("   2. Change any passwords transmitted via Telnet")
        print("   3. Implement network monitoring for Telnet usage")
        print("   4. Establish secure remote access policies")
        
    except Exception as e:
        print(f"❌ Summary generation failed: {e}")
    
    print()
    print("=" * 70)
    print("Demo completed! Telnet analysis capabilities fully operational.")
    print("=" * 70)

if __name__ == "__main__":
    main()