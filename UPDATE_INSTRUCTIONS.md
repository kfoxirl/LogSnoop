# Updating LogSnoop in Kali Linux VM

## Method 1: Git Pull Update (Recommended)

If you originally cloned the repository:

```bash
# Navigate to your LogSnoop directory
cd ~/LogSnoop  # or wherever you cloned it

# Check current status
git status

# Pull the latest changes
git pull origin main

# Install new dependencies (for PCAP functionality)
pip3 install -r requirements.txt

# Or specifically install the new Scapy dependency
pip3 install scapy>=2.4.5

# Verify the update worked
python3 cli.py list-plugins
```

## Method 2: Fresh Clone

If you want to start fresh or don't have git history:

```bash
# Remove old directory (backup any custom files first!)
rm -rf ~/LogSnoop

# Clone the latest version
git clone https://github.com/kfoxirl/LogSnoop.git
cd LogSnoop

# Install dependencies
pip3 install -r requirements.txt

# Test the installation
python3 cli.py list-plugins
```

## Method 3: Download ZIP (Alternative)

If you prefer not to use git:

```bash
# Download and extract
wget https://github.com/kfoxirl/LogSnoop/archive/main.zip
unzip main.zip
cd LogSnoop-main

# Install dependencies
pip3 install -r requirements.txt

# Test
python3 cli.py list-plugins
```

## ✅ Verification Steps

After updating, verify you have the new features:

```bash
# Check plugin count (should show 8 plugins including pcap_network)
python3 cli.py list-plugins

# Test PCAP plugin specifically
python3 cli.py list-plugins | grep pcap_network

# Check for FTP queries (should show ftp_analysis, ftp_transfers, etc.)
python3 cli.py list-plugins | grep -A 5 pcap_network
```

## 🆕 New Features Available After Update

### PCAP Network Analysis Plugin
- **Purpose**: Analyze network packet capture files (.pcap, .pcapng)
- **Queries**: 23 different network analysis types
- **Use Cases**: Network forensics, security analysis, traffic monitoring

### FTP File Transfer Analysis (Your Requested Feature!)
- `ftp_analysis` - Comprehensive FTP traffic overview
- `ftp_transfers` - Upload/download tracking with file sizes
- `ftp_file_sizes` - File size statistics and distribution  
- `ftp_sessions` - FTP session analysis and patterns
- `ftp_commands` - FTP command frequency analysis

### Example Usage

```bash
# Parse a PCAP file with FTP traffic
python3 cli.py parse capture.pcap pcap_network

# Analyze FTP file transfers (answers your original question!)
python3 cli.py query capture.pcap ftp_transfers

# Get detailed file size analysis
python3 cli.py query capture.pcap ftp_file_sizes

# Interactive mode for guided analysis
python3 cli.py interactive
```

## 🔧 Troubleshooting

### If Scapy Installation Fails:
```bash
# On Kali Linux, you might need system packages
sudo apt update
sudo apt install python3-scapy

# Or install via pip with system packages
sudo apt install python3-pip python3-dev
pip3 install scapy
```

### If Import Errors Occur:
```bash
# Check Python path
python3 -c "import sys; print(sys.path)"

# Test Scapy installation
python3 -c "from scapy.all import rdpcap; print('Scapy works!')"
```

### Permissions Issues:
```bash
# If you need to run with elevated privileges for network analysis
sudo python3 cli.py parse capture.pcap pcap_network
```

## 📊 What's New in This Update

- **8 Total Plugins**: SSH, FTP, HTTP, IIS, Tomcat, Simple Login, SKY Binary, PCAP Network
- **Network Forensics**: Port scan detection, failed connections, protocol analysis
- **FTP Forensics**: Upload/download size tracking, session analysis, command monitoring
- **Production Ready**: Full error handling, cross-platform support, comprehensive testing

Perfect for network security analysis on Kali Linux! 🔐