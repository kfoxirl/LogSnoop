#!/usr/bin/env python3
"""
FTP PCAP Troubleshooting Guide
Common issues and solutions for FTP file size detection
"""

print("""
🔍 FTP PCAP Analysis Troubleshooting Guide
==========================================

If you're seeing incorrect file sizes (like 87 bytes), here are common causes:

1. 📊 PACKET SIZE vs FILE SIZE
   - The tool might be showing packet size instead of file transfer size
   - FTP transfers happen over multiple packets
   - Need to correlate control channel commands with data channel transfers

2. 🔗 FTP PROTOCOL COMPLEXITY
   - Control Channel (port 21): Commands and responses
   - Data Channel (variable port): Actual file data
   - Need to match STOR/RETR commands with data transfers

3. 📦 SIZE COMMAND RESPONSES
   - FTP SIZE command returns file size before transfer
   - Response format: "213 <bytes>"
   - Tool should extract this number, not packet size

4. 🏁 TRANSFER COMPLETION
   - FTP sends "226 Transfer complete" with byte count
   - Format varies: "226 Transfer complete (1234 bytes)"
   - Need regex parsing to extract actual bytes

🛠️ DEBUGGING STEPS:

Step 1: Run the debug script
   python3 debug_pcap_ftp.py your_capture.pcap

Step 2: Check for FTP traffic
   - Look for port 21 traffic (control channel)
   - Check for STOR/RETR commands
   - Verify SIZE responses (213 codes)

Step 3: Examine data channel
   - High-numbered ports (>1024) with large payloads
   - Should correlate with control channel timing

Step 4: Manual verification
   - Open PCAP in Wireshark
   - Filter: ftp or tcp.port == 21
   - Look for SIZE responses and completion messages

🔧 COMMON FIXES:

Fix 1: Improve SIZE response parsing
   - Look for "213 <number>" responses
   - Extract the number after "213 "

Fix 2: Better transfer completion parsing  
   - Look for "226" responses with "bytes" keyword
   - Use regex to find byte counts in completion messages

Fix 3: Data channel correlation
   - Sum up data packets between STOR/RETR and completion
   - Match timing between control and data channels

Fix 4: Protocol-specific handling
   - Some FTP servers format responses differently
   - May need server-specific parsing rules

📝 EXPECTED OUTPUT FORMAT:

Correct FTP analysis should show:
   - ftp_transfers: Lists each file with correct byte count
   - ftp_file_sizes: Statistics based on actual file sizes
   - Upload/download breakdown with proper totals

If you see 87 bytes consistently, it's likely:
   - Parsing packet headers instead of FTP responses
   - Missing SIZE command responses  
   - Not correlating data channel with control channel

🚀 NEXT STEPS:

1. Share your PCAP file for analysis
2. Run: python3 debug_pcap_ftp.py your_file.pcap
3. Check the debug output for FTP packet details
4. Look for SIZE responses and completion messages

The debug script will show exactly what FTP traffic is detected
and help identify why file sizes aren't being calculated correctly.
""")

# Additional helper function
def quick_pcap_check():
    """Quick check if Scapy can read PCAP files."""
    try:
        from scapy.all import rdpcap
        print("✅ Scapy is available and can read PCAP files")
        return True
    except ImportError:
        print("❌ Scapy not installed. Install with: pip install scapy")
        return False
    except Exception as e:
        print(f"❌ Scapy error: {e}")
        return False

if __name__ == "__main__":
    quick_pcap_check()