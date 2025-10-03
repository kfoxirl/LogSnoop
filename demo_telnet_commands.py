#!/usr/bin/env python3
"""
Telnet Command Extraction Demo

This demo specifically showcases the command extraction and analysis capabilities
of the LogSnoop Telnet plugin, demonstrating how commands executed during Telnet
sessions can be reconstructed from network packet captures.
"""

import os
import sys
from pathlib import Path

# Add the logsnoop module to the path
sys.path.insert(0, str(Path(__file__).parent))

from logsnoop.core import LogParser

def main():
    """Demonstrate Telnet command extraction and analysis."""
    
    print("=" * 70)
    print("TELNET COMMAND EXTRACTION & ANALYSIS DEMO")
    print("=" * 70)
    print()
    print("This demo shows how LogSnoop can extract and analyze commands")
    print("executed during Telnet sessions from network packet captures.")
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
    
    # Run command analysis
    print("⌨️  RUNNING COMMAND EXTRACTION ANALYSIS")
    print("-" * 50)
    
    try:
        cmd_result = parser.query_logs("pcap_network", "telnet_commands", 
                                     file_id=file_id, file_path=pcap_file)
        
        if "error" in cmd_result:
            print(f"❌ Error: {cmd_result['error']}")
            return
        
        # Display command summary
        total_commands = cmd_result.get('total_commands', 0)
        unique_commands = cmd_result.get('unique_commands', 0)
        
        print(f"🔍 Command Analysis Results:")
        print(f"   📊 Total Commands Found: {total_commands}")
        print(f"   🆔 Unique Commands: {unique_commands}")
        
        if cmd_result.get('analysis_note'):
            print(f"   📝 Analysis Method: {cmd_result['analysis_note']}")
        print()
        
        # Display extracted commands
        commands = cmd_result.get('commands', [])
        if commands:
            print("💻 EXTRACTED COMMANDS:")
            print("=" * 50)
            
            for i, cmd in enumerate(commands, 1):
                timestamp = cmd.get('timestamp', '')
                if timestamp:
                    # Format timestamp nicely
                    timestamp = timestamp[:19].replace('T', ' ')
                
                command = cmd.get('command', '')
                category = cmd.get('category', 'unknown')
                client_ip = cmd.get('client_ip', '')
                server_ip = cmd.get('server_ip', '')
                
                # Category descriptions
                category_info = {
                    'system_info': 'System Information Query',
                    'session': 'Session Management',
                    'directory': 'Directory Navigation',
                    'file_view': 'File Viewing',
                    'file_copy': 'File Operations',
                    'file_delete': 'File Deletion',
                    'privilege': 'Privilege Escalation',
                    'network': 'Network Operations',
                    'process': 'Process Management',
                    'download': 'File Download',
                    'other': 'Other Command'
                }
                
                category_desc = category_info.get(category, 'Unknown')
                
                # Category emojis
                category_emoji = {
                    'system_info': '🖥️',
                    'session': '🚪',
                    'directory': '📁',
                    'file_view': '📄',
                    'file_copy': '📋',
                    'file_delete': '🗑️',
                    'privilege': '👑',
                    'network': '🌐',
                    'process': '⚙️',
                    'download': '⬇️',
                    'other': '❓'
                }
                
                emoji = category_emoji.get(category, '❓')
                
                print(f"Command #{i}:")
                print(f"  {emoji} Command: {command}")
                print(f"  ⏰ Executed: {timestamp}")
                print(f"  🏷️  Category: {category_desc}")
                print(f"  🖥️  Client: {client_ip}")
                print(f"  🌐 Server: {server_ip}")
                
                # Add command-specific analysis
                if command.lower().startswith('uname'):
                    print(f"  📋 Analysis: System reconnaissance command - gathers OS information")
                    print(f"  ⚠️  Risk: Information disclosure about target system")
                elif command.lower() in ['exit', 'logout']:
                    print(f"  📋 Analysis: Normal session termination")
                    print(f"  ✅ Risk: Low - standard logout procedure")
                
                print()
            
        else:
            print("ℹ️  No commands were extracted from this session")
            print("   This could mean:")
            print("   • Session was authentication-only")
            print("   • Commands were not successfully transmitted")
            print("   • Session was interrupted before command execution")
            print()
        
        # Command categorization analysis
        categories = cmd_result.get('command_categories', {})
        if categories:
            print("📊 COMMAND CATEGORIZATION:")
            print("-" * 30)
            
            category_risks = {
                'system_info': '🟡 Medium - Information gathering',
                'session': '🟢 Low - Normal session management',
                'directory': '🟢 Low - File system navigation',
                'file_view': '🟡 Medium - Data access',
                'file_copy': '🟠 High - Data manipulation',
                'file_delete': '🔴 Critical - Data destruction',
                'privilege': '🔴 Critical - Privilege escalation',
                'network': '🟠 High - Network reconnaissance',
                'process': '🟡 Medium - System monitoring',
                'download': '🔴 Critical - Potential malware',
                'other': '🟡 Medium - Unknown operations'
            }
            
            for category, count in categories.items():
                risk = category_risks.get(category, '❓ Unknown risk')
                print(f"  • {category}: {count} command(s) - {risk}")
            print()
        
        # Display extracted system information
        system_info = cmd_result.get('system_information', {})
        if system_info and any(v for v in system_info.values() if v):
            print("🖥️  EXTRACTED SYSTEM INFORMATION:")
            print("=" * 40)
            
            if system_info.get('hostname'):
                print(f"🏠 Hostname: {system_info['hostname']}")
            
            if system_info.get('operating_system'):
                os_info = system_info['operating_system']
                if system_info.get('kernel_version'):
                    os_info += f" (Kernel: {system_info['kernel_version']})"
                print(f"💿 Operating System: {os_info}")
            
            if system_info.get('cpu_architecture'):
                print(f"🔧 CPU Architecture: {system_info['cpu_architecture']}")
            
            if system_info.get('architecture_description'):
                print(f"📋 Architecture Details: {system_info['architecture_description']}")
            
            if system_info.get('build_info'):
                print(f"🏗️  Build Information: {system_info['build_info']}")
            
            if system_info.get('system_output'):
                print(f"\n📄 Raw System Output:")
                print(f"   {system_info['system_output']}")
            
            print("\n💡 Analysis:")
            print("   This system information was revealed when the user executed 'uname -a'")
            print("   and demonstrates how Telnet exposes system details to network monitors.")
            print()
        
        # Security analysis
        security = cmd_result.get('security_analysis', {})
        if security:
            print("🛡️  SECURITY ASSESSMENT:")
            print("-" * 25)
            
            concerns = []
            if security.get('system_info_commands', 0) > 0:
                concerns.append(f"🖥️  {security['system_info_commands']} system information queries detected")
            if security.get('privileged_commands', 0) > 0:
                concerns.append(f"👑 {security['privileged_commands']} privileged operations detected")
            if security.get('file_operations', 0) > 0:
                concerns.append(f"📄 {security['file_operations']} file operations detected")
            if security.get('suspicious_downloads', 0) > 0:
                concerns.append(f"⬇️  {security['suspicious_downloads']} suspicious downloads detected")
            if security.get('network_commands', 0) > 0:
                concerns.append(f"🌐 {security['network_commands']} network commands detected")
            
            if concerns:
                for concern in concerns:
                    print(f"   {concern}")
            else:
                print("   ✅ No high-risk command patterns detected")
            
            print()
        
        # Timeline analysis
        if len(commands) > 1:
            print("⏰ COMMAND TIMELINE:")
            print("-" * 20)
            
            timeline = cmd_result.get('command_timeline', commands)
            for i, cmd in enumerate(timeline):
                timestamp = cmd.get('timestamp', '')[:19].replace('T', ' ')
                command = cmd.get('command', '')
                print(f"   {i+1}. {timestamp} - {command}")
            print()
        
        # Forensic summary
        print("🔬 FORENSIC ANALYSIS SUMMARY:")
        print("-" * 35)
        print("✅ Command extraction successful")
        print("✅ Timeline reconstruction complete")
        print("✅ Security categorization applied")
        print("✅ Risk assessment performed")
        
        if total_commands > 0:
            print(f"\n📋 Key Findings:")
            print(f"   • User executed {total_commands} command(s) during session")
            print(f"   • Commands span {len(categories)} different categories")
            
            # Highlight any concerning activity
            if any(cat in categories for cat in ['privilege', 'file_delete', 'download']):
                print(f"   ⚠️  High-risk command categories detected")
            else:
                print(f"   ✅ No immediately concerning command patterns")
        
    except Exception as e:
        print(f"❌ Command analysis failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("=" * 70)
    print("COMMAND EXTRACTION DEMO COMPLETE")
    print("=" * 70)
    print()
    print("This demonstration shows how LogSnoop can:")
    print("• Reconstruct commands from character-by-character Telnet input")
    print("• Categorize commands by type and security risk level")
    print("• Provide timeline analysis of command execution")
    print("• Assess security implications of executed commands")
    print("• Support forensic investigation of user activities")
    print()
    print("⚠️  Use cases for command extraction:")
    print("   - Incident response and forensic investigation")
    print("   - Security monitoring and threat hunting")
    print("   - Compliance auditing and activity logging")
    print("   - Insider threat detection")
    print("   - Attack pattern analysis")

if __name__ == "__main__":
    main()