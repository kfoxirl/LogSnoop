#!/usr/bin/env python3
"""
Telnet Credential Extraction Demo

This demo specifically showcases the credential extraction capabilities
of the LogSnoop Telnet analysis plugin, demonstrating how plaintext
credentials can be recovered from network captures.
"""

import os
import sys
from pathlib import Path

# Add the logsnoop module to the path
sys.path.insert(0, str(Path(__file__).parent))

from logsnoop.core import LogParser

def main():
    """Demonstrate Telnet credential extraction."""
    
    print("=" * 70)
    print("TELNET CREDENTIAL EXTRACTION DEMO")
    print("=" * 70)
    print()
    print("This demo shows how LogSnoop can extract plaintext credentials")
    print("from Telnet network captures for forensic analysis.")
    print()
    
    # Initialize parser
    parser = LogParser()
    
    # Parse the Telnet PCAP file
    pcap_file = "test_data/Telnet.pcap"
    
    if not os.path.exists(pcap_file):
        print(f"❌ Error: {pcap_file} not found!")
        return
    
    print(f"📁 Analyzing PCAP file: {pcap_file}")
    
    try:
        result = parser.parse_log_file(pcap_file, "pcap_network")
        file_id = result['file_id']
        print(f"✅ Successfully parsed file (ID: {file_id})")
        if result.get('duplicate'):
            print("ℹ️  Using previously parsed data")
        print()
    except Exception as e:
        print(f"❌ Error parsing file: {e}")
        return
    
    # Run authentication analysis
    print("🔐 RUNNING CREDENTIAL EXTRACTION ANALYSIS")
    print("-" * 50)
    
    try:
        auth_result = parser.query_logs("pcap_network", "telnet_authentication", 
                                      file_id=file_id, file_path=pcap_file)
        
        if "error" in auth_result:
            print(f"❌ Error: {auth_result['error']}")
            return
        
        # Display authentication summary
        print(f"🔍 Authentication Attempts Found: {auth_result.get('total_auth_attempts', 0)}")
        print(f"✅ Successful Logins: {auth_result.get('successful_attempts', 0)}")
        print(f"❌ Failed Attempts: {auth_result.get('failed_attempts', 0)}")
        print()
        
        # Show security warning
        if auth_result.get('security_warning'):
            print(f"🚨 {auth_result['security_warning']}")
            print()
        
        # Display captured credentials
        credentials = auth_result.get('captured_credentials', [])
        if credentials:
            print("🔓 EXTRACTED CREDENTIALS:")
            print("=" * 40)
            
            for i, cred in enumerate(credentials, 1):
                username = cred.get('username', '[Unknown]').replace('\x00', '').strip()
                password = cred.get('password', '[Unknown]').replace('\x00', '').strip()
                
                print(f"Credential Set #{i}:")
                print(f"  👤 Username: '{username}'")
                print(f"  🔑 Password: '{password}'")
                print()
            
            print("⚠️  SECURITY IMPLICATIONS:")
            print("   • These credentials were transmitted in PLAINTEXT")
            print("   • Anyone monitoring network traffic could capture them")
            print("   • No encryption or protection was used")
            print("   • Credentials are now compromised and should be changed")
            print()
        else:
            print("ℹ️  No complete credential sets were captured")
            print()
        
        # Show detailed authentication sequence
        auth_events = auth_result.get('authentication_events', [])
        if auth_events and len(auth_events) > 0:
            print("📋 DETAILED AUTHENTICATION SEQUENCE:")
            print("-" * 40)
            
            event = auth_events[0]  # First (and likely only) session
            print(f"Session: {event.get('session', 'Unknown')}")
            print(f"Client IP: {event.get('client_ip', 'Unknown')}")
            print(f"Server IP: {event.get('server_ip', 'Unknown')}")
            print()
            
            print("Authentication Flow:")
            for seq_event in event.get('auth_sequence', []):
                timestamp = seq_event.get('timestamp', '')[:19]  # Remove microseconds
                event_type = seq_event.get('event', 'unknown')
                direction = seq_event.get('direction', '')
                data = seq_event.get('data', '')
                
                # Format direction for display
                dir_display = "Server→Client" if direction == "S->C" else "Client→Server"
                
                # Special formatting for different event types
                if event_type == "login_prompt":
                    print(f"  {timestamp} [{dir_display}] 🖥️  Server requests login")
                elif event_type == "username_input":
                    print(f"  {timestamp} [{dir_display}] 👤 Username character: '{data}'")
                elif event_type == "password_prompt":
                    print(f"  {timestamp} [{dir_display}] 🖥️  Server requests password")
                elif event_type == "password_input":
                    print(f"  {timestamp} [{dir_display}] 🔑 Password character: '{data}'")
                elif event_type == "auth_success":
                    print(f"  {timestamp} [{dir_display}] ✅ Authentication successful (prompt: '{data}')")
                elif event_type == "auth_failure":
                    print(f"  {timestamp} [{dir_display}] ❌ Authentication failed: {data}")
                else:
                    print(f"  {timestamp} [{dir_display}] ⚪ {event_type}: {data}")
            print()
        
        # Show forensic recommendations
        print("🔬 FORENSIC ANALYSIS SUMMARY:")
        print("-" * 40)
        print("✅ Successfully extracted plaintext credentials from network capture")
        print("✅ Reconstructed complete authentication sequence with timestamps")
        print("✅ Identified source and destination IP addresses")
        print("✅ Documented security vulnerabilities in the communication")
        print()
        
        print("🛡️  SECURITY RECOMMENDATIONS:")
        print("-" * 30)
        for i, rec in enumerate(auth_result.get('recommendations', [])[:3], 1):
            print(f"{i}. {rec}")
        
        print()
        print("📊 THREAT ASSESSMENT:")
        security_summary = auth_result.get('security_summary', {})
        print(f"   • Credentials Captured: {security_summary.get('credentials_captured', 0)}")
        print(f"   • Brute Force Indicators: {security_summary.get('brute_force_indicators', False)}")
        print(f"   • Multiple Users Detected: {security_summary.get('multiple_users', False)}")
        
    except Exception as e:
        print(f"❌ Credential extraction failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print()
    print("This demonstration shows how LogSnoop can:")
    print("• Extract plaintext usernames and passwords from Telnet captures")
    print("• Reconstruct authentication sequences with precise timing")
    print("• Provide forensic evidence of credential compromise")
    print("• Assess security risks and provide remediation guidance")
    print()
    print("⚠️  Remember: Use this capability responsibly and only for:")
    print("   - Authorized security testing and auditing")
    print("   - Incident response and forensic investigation")
    print("   - Educational and training purposes")
    print("   - Compliance and security assessments")

if __name__ == "__main__":
    main()