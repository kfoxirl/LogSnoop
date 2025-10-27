# LogSnoop - Python Log Parser with Plugin Architecture

LogSnoop is a comprehensive forensic analysis and log parsing framework with an extensible plugin architecture. It supports analyzing network traffic, server logs, binary formats, database files, and security events - making it ideal for incident response, digital forensics, and security investigations.

## Features

- **🔌 Plugin Architecture**: Easily extensible with custom log parsers and forensic analyzers
- **📊 Multiple Log Types**: Built-in support for 12+ log formats including SSH, FTP, HTTP, IIS, Tomcat, and more
- **🌐 Network Forensics**: Comprehensive PCAP analysis with HTTP, FTP, Telnet, TLS, DNS, and custom protocol support
- **💳 Payment Card Forensics**: EMV transaction analysis with fraud detection capabilities
- **🗄️ Database Analysis**: SQLite database inspection, corruption detection, and forensic carving
- **🌲 Process Trees**: Parse and analyze process hierarchies with PID/PPID relationships
- **📁 Binary Format Support**: Custom SKY binary log format and CAN bus vehicle telemetry
- **🎯 Interactive Mode**: User-friendly guided interface with tab completion and visual results
- **💾 Flat File Database**: Simple JSON-based storage with no external dependencies
- **🔍 Rich Querying**: Comprehensive query system for each log type (100+ queries)
- **📋 Interactive Table View**: Paginated table display with `less`-like navigation
- **⚡ CLI Interface**: Powerful command-line tool for parsing and querying logs
- **📈 Statistics**: Automatic generation of summary statistics and analytics
- **🔎 Filtering & Search**: Filter log entries by IP addresses, protocols, ports, and other criteria

## Supported Log Types & Forensic Modules

### 1. SSH Authentication Logs (`ssh_auth`)
- Parses SSH authentication logs (auth.log, secure)
- Tracks failed/successful logins, connections, disconnections
- Identifies suspicious login patterns and brute force attacks
- **Queries**: `failed_logins`, `successful_logins`, `connection_count`, `suspicious_logins`, `top_attackers`, `login_attempts_by_user`, `connections_by_ip`

### 2. FTP Server Logs (`ftp_log`)  
- Parses FTP server logs (vsftpd, proftpd)
- Tracks uploads, downloads, file operations, bytes transferred
- Monitors login attempts and user activity
- **Queries**: `uploads`, `downloads`, `login_attempts`, `failed_logins`, `successful_logins`, `bytes_transferred`, `top_uploaders`, `top_downloaders`, `file_operations`, `connections_by_ip`

### 3. HTTP Access Logs (`http_access`)
- Parses HTTP web server access logs (Apache, Nginx)
- Tracks requests, status codes, bandwidth usage, response times
- Analyzes traffic patterns and errors
- **Queries**: `requests_by_status`, `requests_by_ip`, `requests_by_path`, `error_requests`, `bytes_served`, `top_pages`, `top_referrers`, `top_user_agents`, `bandwidth_usage`, `response_time_stats`

### 4. Simple Login Logs (`simple_login`)
- Parses simple login logs with timestamp, IP, username format
- Tracks user login patterns and frequency
- **Queries**: `logins_by_user`, `logins_by_ip`, `login_count`, `unique_users`, `unique_ips`, `login_timeline`, `frequent_users`, `frequent_ips`

### 5. SKY Binary Logs (`sky_log`)
- Parses SKY binary network traffic logs (custom binary format)
- Tracks network connections, data transfers, bandwidth usage
- Supports header metadata (hostname, flags, creation timestamp)
- Vehicle telemetry: Decodes CAN bus frames from SocketCAN PCAP captures with speed analytics
- **Queries**: `traffic_by_ip`, `top_talkers`, `traffic_summary`, `bytes_by_source`, `bytes_by_destination`, `connections_by_source`, `connections_by_destination`, `traffic_timeline`, `ip_pairs`, `bandwidth_usage`

### 6. Apache Tomcat Logs (`tomcat_log`)
- Parses Apache Tomcat server logs (access.log, catalina.out)
- Supports both access logs and catalina application logs
- Tracks HTTP requests, response times, errors, and exceptions
- Analyzes application errors, session data, and performance metrics
- **Queries**: `requests_by_status`, `requests_by_ip`, `requests_by_path`, `error_requests`, `slow_requests`, `bytes_served`, `top_pages`, `top_user_agents`, `bandwidth_usage`, `response_time_stats`, `requests_by_method`, `session_analysis`, `exception_summary`, `daily_traffic`, `catalina_errors`, `application_errors`

### 7. Microsoft IIS Logs (`iis_log`)
- Parses Microsoft IIS server logs (W3C Extended format)
- Tracks HTTP requests, response codes, bandwidth, and response times
- Supports IIS-specific features like Win32 status codes and ASP.NET errors
- Analyzes multiple sites, client errors, server errors, and protocols
- **Queries**: `requests_by_status`, `requests_by_ip`, `requests_by_path`, `error_requests`, `slow_requests`, `bytes_served`, `top_pages`, `top_user_agents`, `bandwidth_usage`, `response_time_stats`, `requests_by_method`, `requests_by_site`, `win32_status_analysis`, `daily_traffic`, `client_errors`, `server_errors`, `asp_net_errors`, `top_referrers`, `query_string_analysis`, `protocol_analysis`

### 8. Process Tree Logs (`process_tree`)
- Parses JSON arrays of process events with fields like timestamp, process_name, process_id (PID), parent_process_id (PPID), image path, command line, and md5
- Tracks parent-child relationships for incident response and threat hunting
- Identifies process chains, suspicious spawns, and command-line analysis
- **Queries**: `process_list`, `count_by_name`, `children_of`, `tree_from_pid`, `top_parents`, `commandline_search`, `suspicious_spawns`

### 9. PCAP Network Traffic (`pcap_network`) 🔥
**Comprehensive network forensics with 30+ analysis queries**

#### General Network Analysis
- Protocol breakdown, bandwidth usage, connection analysis
- Port scan detection, failed connections, data transfer analysis
- TCP flags analysis, packet size statistics, traffic timeline
- **Queries**: `top_talkers`, `protocol_breakdown`, `bandwidth_usage`, `connection_analysis`, `port_scan_detection`, `suspicious_ports`, `failed_connections`, `data_transfer_analysis`, `tcp_flags_analysis`, `packet_size_stats`, `traffic_timeline`, `top_destinations`, `geo_traffic`

#### HTTP/HTTPS Traffic Analysis
- Request/response analysis with full transaction reconstruction
- Status codes, methods, user agents, content types
- Security analysis (suspicious patterns, encoded content)
- File downloads with hash calculation (MD5, SHA1, SHA256)
- Performance metrics and error analysis
- **Queries**: `http_analysis`, `http_transactions`, `http_status_codes`, `http_methods`, `http_user_agents`, `http_hosts`, `http_content_types`, `http_errors`, `http_performance`, `http_security`, `http_file_downloads`, `http_file_hashes`, `http_dump_files`

#### FTP Protocol Analysis
- File transfer tracking (uploads/downloads)
- Session analysis with authentication
- Command/response analysis
- File size statistics
- Downloads table with full file reconstruction
- **Queries**: `ftp_analysis`, `ftp_transfers`, `ftp_file_sizes`, `ftp_sessions`, `ftp_commands`, `ftp_downloads_table`

#### Telnet Traffic Analysis
- Session reconstruction and authentication tracking
- Command execution monitoring
- Interactive traffic analysis
- Security assessment (cleartext credentials)
- **Queries**: `telnet_analysis`, `telnet_sessions`, `telnet_authentication`, `telnet_commands`, `telnet_traffic`, `telnet_security`

#### DNS Query Analysis
- DNS queries and responses
- Top domains and suspicious patterns
- **Queries**: `dns_queries`, `top_domains`

#### TLS/SSL Traffic Analysis
- Encrypted traffic identification and analysis
- Certificate information extraction
- **Query**: `tls_analysis`

#### Custom Protocol Analysis
- Pandora protocol decoder (CTF/specialized protocols)
- **Query**: `pandora_analysis`

### 10. EMV Payment Card Transactions (`emv`) 💳
**Credit/debit card transaction forensics and fraud detection**

- Parses EMV (Europay, Mastercard, Visa) transaction logs
- Analyzes Tag 55 data containing EMV transaction details in TLV format
- Reconstructs Primary Account Numbers (PANs) from fragments using Luhn algorithm
- Detects magstripe fallback fraud (chip cards used as swipe)
- Identifies suspicious transaction patterns and velocity
- Geographic analysis with Terminal Country Code (ISO 3166-1)
- Transaction type classification (purchase, cash withdrawal, refund, etc.)
- Application Transaction Counter (ATC) analysis for duplicate detection
- **Queries**: `transaction_summary`, `fraud_indicators`, `magstripe_analysis`, `country_analysis`, `pan_reconstruction`, `transaction_types`, `amount_analysis`, `duplicate_detection`

**Key EMV Tags Parsed**:
- 9F36: Application Transaction Counter (ATC)
- 9A: Transaction Date
- 9F02: Amount, Authorized  
- 82: Application Interchange Profile (AIP) - Magstripe vs Chip indicator
- 95: Terminal Verification Results (TVR)
- 9F1A: Terminal Country Code
- 9C: Transaction Type

### 11. SQLite Database Files (`sqlite_db`) 🗄️
**Database forensics and corruption recovery**

- Analyzes SQLite .db files for forensic investigation
- Repairs corrupted SQLite headers automatically
- Lists tables with root page numbers
- Detects and reports corrupted/unreadable tables
- Forensic data carving from database pages
- Schema extraction and metadata analysis
- **Queries**: `header_info`, `list_tables`, `bad_tables`, `page_size`, `answer_q1`, `answer_q2`, `answer_q3`, `carve_roster`

**Capabilities**:
- Automatic header repair (creates temporary fixed copy)
- Page-level corruption detection
- Table readability assessment
- Direct binary analysis of database structure
- Forensic carving of deleted or corrupted data

## Installation

### Quick Installation (Linux/macOS)
```bash
# Clone the repository
git clone https://github.com/kfoxirl/LogSnoop.git
cd LogSnoop

# Install for current user (recommended)
make install-user

# OR install system-wide (requires sudo)
sudo make install-system
```

### Windows Installation
```batch
# Clone the repository
git clone https://github.com/kfoxirl/LogSnoop.git
cd LogSnoop

# Run the Windows installer
install.bat
```

### Manual Installation
```bash
# Clone and setup virtual environment
git clone https://github.com/kfoxirl/LogSnoop.git
cd LogSnoop
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Use directly
python cli.py --help
```

### Installation Options
- **User Installation**: `make install-user` - Installs to `~/.local/` (no sudo required)
- **System Installation**: `sudo make install-system` - Installs to `/usr/local/` (available for all users)
- **Custom Location**: `make install PREFIX=/opt/logsnoop` - Install to custom directory
- **Windows**: `install.bat` - Automated Windows installation with PATH setup

### Post-Installation
After installation, LogSnoop is available as a system command:
```bash
# View manual page
man logsnoop

# Run LogSnoop
logsnoop --help
logsnoop list-plugins
```

## Usage

LogSnoop offers both a **command-line interface** for advanced users and an **interactive mode** for beginners.

### 🎯 Interactive Mode (Recommended for New Users)

Start the user-friendly interactive mode with guided workflows:

```bash
logsnoop interactive
```

The interactive mode provides:
- 🎯 **Guided file parsing** with plugin selection assistance
- 🔍 **Query builder** with descriptions and examples  
- 📊 **Visual results** with formatted output and colors
- 📋 **Table browser** integration
- 🔌 **Plugin information** with supported queries
- ✅ **Input validation** and helpful error messages
- ⭐ **Tab completion** for file paths (just like your shell!)
- 🚀 **No command memorization needed!**

#### 💡 Pro Tip: Tab Completion
When entering file paths in interactive mode, press **TAB** to:
- Auto-complete directory and file names
- Browse available files and folders
- Navigate through directory structures
- Discover log files without typing full paths

Works on all platforms (Linux/Mac/Windows) with automatic fallback.

### Command Line Interface (Advanced Users)

#### List Available Plugins
```bash
logsnoop list-plugins
```

#### Parse a Log File
```bash
# Parse SSH authentication log
logsnoop parse /var/log/auth.log ssh_auth

# Parse FTP log with custom database
logsnoop parse /var/log/vsftpd.log ftp_log --db custom.db

# Parse HTTP access log
logsnoop parse /var/log/apache2/access.log http_access

# Parse SKY binary log
logsnoop parse network_traffic.sky sky_log

# Parse a Process Tree JSON
logsnoop parse processtree.json process_tree

# Parse Tomcat access log
logsnoop parse /opt/tomcat/logs/localhost_access_log.txt tomcat_log

# Parse Tomcat catalina log
logsnoop parse /opt/tomcat/logs/catalina.out tomcat_log

# Parse IIS log
logsnoop parse /inetpub/logs/LogFiles/W3SVC1/ex231002.log iis_log

# Parse PCAP network traffic
logsnoop parse network_capture.pcap pcap_network

# Parse PCAPNG file
logsnoop parse traffic.pcapng pcap_network

# Parse EMV transaction log
logsnoop parse emv_transactions.log emv

# Parse SQLite database file
logsnoop parse mystery.db sqlite_db
```

#### Query Parsed Logs
```bash
# SSH Analysis
logsnoop query ssh_auth failed_logins
logsnoop query ssh_auth top_attackers --limit 5
logsnoop query ssh_auth failed_logins --by-ip

# FTP Analysis
logsnoop query ftp_log bytes_transferred --by-user
logsnoop query ftp_log file_operations --by-type

# HTTP Analysis
logsnoop query http_access requests_by_status
logsnoop query http_access error_requests --by-status

# Login Analysis
logsnoop query simple_login login_timeline --period day

# SKY Binary Analysis
logsnoop query sky_log traffic_summary
logsnoop query sky_log top_talkers --limit 10 --by-bytes
logsnoop query sky_log ip_pairs --limit 10 --sort-by bytes

# Tomcat Analysis
logsnoop query tomcat_log error_requests --limit 20
logsnoop query tomcat_log response_time_stats
logsnoop query tomcat_log exception_summary --limit 10

# IIS Analysis
logsnoop query iis_log requests_by_site
logsnoop query iis_log win32_status_analysis --limit 15
logsnoop query iis_log asp_net_errors

# PCAP Network Analysis
logsnoop query pcap_network protocol_breakdown
logsnoop query pcap_network top_talkers --limit 10
logsnoop query pcap_network port_scan_detection

# PCAP HTTP Analysis
logsnoop query pcap_network http_analysis
logsnoop query pcap_network http_file_downloads
logsnoop query pcap_network http_file_hashes

# PCAP FTP Analysis
logsnoop query pcap_network ftp_analysis
logsnoop query pcap_network ftp_transfers
logsnoop query pcap_network ftp_downloads_table

# PCAP Telnet Analysis
logsnoop query pcap_network telnet_analysis
logsnoop query pcap_network telnet_authentication
logsnoop query pcap_network telnet_commands

# PCAP DNS Analysis
logsnoop query pcap_network dns_queries
logsnoop query pcap_network top_domains

# PCAP TLS Analysis
logsnoop query pcap_network tls_analysis

# EMV Payment Card Analysis
logsnoop query emv transaction_summary
logsnoop query emv fraud_indicators
logsnoop query emv magstripe_analysis
logsnoop query emv country_analysis

# SQLite Database Analysis
logsnoop query sqlite_db header_info
logsnoop query sqlite_db list_tables
logsnoop query sqlite_db bad_tables
logsnoop query sqlite_db carve_roster

# Process Tree Analysis
logsnoop query process_tree process_list
logsnoop query process_tree tree_from_pid --pid 1234
logsnoop query process_tree commandline_search --pattern "powershell"
```

#### List Parsed Files
```bash
logsnoop list-files
```

#### Show File Summary
```bash
logsnoop summary 1  # Show summary for file ID 1
```

#### View Log Entries in Table Format
```bash
# View all entries for a plugin in paginated table format
logsnoop view sky_log

# View specific file entries
logsnoop view sky_log --file-id 1

# Customize page size (default: 20)
logsnoop view sky_log --page-size 10

# Filter by IP address
logsnoop view sky_log --ip 192.168

# Limit total entries shown
logsnoop view sky_log --limit 100

# Disable screen clearing for terminal compatibility
logsnoop view sky_log --no-clear

# Combine options
logsnoop view sky_log --file-id 1 --ip 77.255 --page-size 5
```

**Table View Navigation:**
- `n` or `next` - Go to next page
- `p` or `prev` - Go to previous page
- `g[num]` - Go to specific page (e.g., `g5` or `g 5`)
- `q` or `quit` - Exit table view
- `h` or `help` - Show navigation help

**Table View Features:**
- **Paginated Display**: Browse through large datasets page by page
- **Filtering**: Filter entries by IP address patterns
- **Sorting**: Entries sorted by file ID and line number for consistency
- **Responsive Layout**: Automatically adjusts column widths based on data
- **Interactive Navigation**: `less`-like navigation with keyboard commands
- **Clean Output**: Well-formatted table with proper borders and alignment

### Python API

```python
from logsnoop.core import LogParser

# Initialize parser
parser = LogParser("my_logs.db")

# List available plugins
plugins = parser.get_available_plugins()
print(plugins)  
# ['ssh_auth', 'ftp_log', 'http_access', 'simple_login', 'sky_log', 
#  'tomcat_log', 'iis_log', 'process_tree', 'pcap_network', 'emv', 'sqlite_db']

# Parse a log file
result = parser.parse_log_file("/var/log/auth.log", "ssh_auth")
print(f"Parsed {result['entries_count']} entries")

# Parse a PCAP file
pcap_result = parser.parse_log_file("capture.pcap", "pcap_network")
print(f"Analyzed {pcap_result['entries_count']} packets")

# Parse an EMV transaction log
emv_result = parser.parse_log_file("transactions.log", "emv")
print(f"Found {emv_result['entries_count']} transactions")

# Query the parsed data
failed_logins = parser.query_logs("ssh_auth", "failed_logins", by_ip=True)
print(failed_logins)

# Query PCAP for HTTP file downloads
downloads = parser.query_logs("pcap_network", "http_file_downloads")
print(downloads)

# Query EMV for fraud indicators
fraud = parser.query_logs("emv", "fraud_indicators")
print(fraud)

# Get summary statistics
summary = parser.get_file_summary(result['file_id'])
print(summary)
```

## Creating Custom Plugins

To create a custom plugin, inherit from `BaseLogPlugin`:

```python
from logsnoop.plugins.base import BaseLogPlugin
from typing import Dict, List, Any

class MyCustomPlugin(BaseLogPlugin):
    @property
    def name(self) -> str:
        return "my_custom"
    
    @property
    def description(self) -> str:
        return "My custom log parser"
    
    @property
    def supported_queries(self) -> List[str]:
        return ["my_query", "another_query"]
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        # Parse log content and return structured data
        entries = []  # List of parsed log entries
        summary = {}  # Summary statistics
        
        # Your parsing logic here
        
        return {
            'entries': entries,
            'summary': summary
        }
    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        # Implement your custom queries
        if query_type == "my_query":
            # Your query logic here
            return results
        else:
            raise ValueError(f"Unsupported query type: {query_type}")
```

Save the plugin as `logsnoop/plugins/my_custom.py` and it will be automatically loaded.

## Database Structure

LogSnoop uses a simple JSON-based flat file database with three main collections:

- **files**: Metadata about parsed log files
- **entries**: Individual parsed log entries
- **summaries**: Summary statistics for each file

## Sample Data Analysis

The project includes sample log files that demonstrate various attack patterns and forensic scenarios:

### SSH Brute Force Analysis
```bash
# Parse SSH auth log
logsnoop parse auth.log ssh_auth

# Find top attackers
logsnoop query ssh_auth top_attackers --limit 10

# Analyze failed login patterns
logsnoop query ssh_auth failed_logins --by-ip
```

### FTP Activity Monitoring
```bash
# Parse FTP log
logsnoop parse vsftpd.log ftp_log

# Check bandwidth usage
logsnoop query ftp_log bytes_transferred --by-user

# Monitor file operations
logsnoop query ftp_log file_operations --by-type
```

### Web Traffic Analysis
```bash
# Parse access log
logsnoop parse access.log http_access

# Check error rates
logsnoop query http_access error_requests --by-status

# Analyze bandwidth usage
logsnoop query http_access bandwidth_usage --period day
```

### Network Traffic Analysis
```bash
# Parse SKY binary log
logsnoop parse network_traffic.sky sky_log

# Get traffic summary
logsnoop query sky_log traffic_summary

# Find top bandwidth consumers
logsnoop query sky_log top_talkers --by-bytes --limit 10
```

### PCAP Network Forensics
```bash
# Parse packet capture
logsnoop parse capture.pcap pcap_network

# Protocol analysis
logsnoop query pcap_network protocol_breakdown
logsnoop query pcap_network bandwidth_usage

# HTTP forensics
logsnoop query pcap_network http_analysis
logsnoop query pcap_network http_file_downloads
logsnoop query pcap_network http_file_hashes

# FTP file transfers
logsnoop query pcap_network ftp_analysis
logsnoop query pcap_network ftp_downloads_table

# Telnet session analysis
logsnoop query pcap_network telnet_analysis
logsnoop query pcap_network telnet_authentication

# Port scanning detection
logsnoop query pcap_network port_scan_detection

# DNS queries
logsnoop query pcap_network dns_queries
logsnoop query pcap_network top_domains
```

### EMV Payment Card Forensics
```bash
# Parse EMV transaction log
logsnoop parse emv_transactions.log emv

# Fraud detection
logsnoop query emv fraud_indicators
logsnoop query emv magstripe_analysis

# Transaction analysis
logsnoop query emv transaction_summary
logsnoop query emv country_analysis
logsnoop query emv amount_analysis

# PAN reconstruction
logsnoop query emv pan_reconstruction
```

### SQLite Database Analysis
```bash
# Analyze database file
logsnoop parse mystery.db sqlite_db

# Check for corruption
logsnoop query sqlite_db header_info
logsnoop query sqlite_db bad_tables

# List all tables
logsnoop query sqlite_db list_tables

# Forensic carving
logsnoop query sqlite_db carve_roster
```

### Process Tree Investigation
```bash
# Parse process events
logsnoop parse processes.json process_tree

# View process hierarchy
logsnoop query process_tree tree_from_pid --pid 1234

# Hunt for suspicious processes
logsnoop query process_tree suspicious_spawns
logsnoop query process_tree commandline_search --pattern "cmd.exe"
```

## Forensic Use Cases

### 🔍 Incident Response
- **Network Intrusion**: Analyze PCAP files for port scans, suspicious connections, data exfiltration
- **Web Attack Analysis**: Examine HTTP logs for SQL injection, XSS, path traversal attempts
- **Brute Force Detection**: Identify SSH/FTP/Telnet authentication attacks
- **Malware Communication**: Track C2 traffic, DNS tunneling, suspicious protocols

### 💳 Financial Fraud Investigation
- **Card Present Fraud**: Detect magstripe fallback on chip cards
- **Transaction Pattern Analysis**: Identify velocity attacks, geographic anomalies
- **PAN Reconstruction**: Recover account numbers from fragmented EMV logs
- **Cross-Border Fraud**: Analyze terminal country codes for suspicious patterns

### 🗄️ Database Forensics
- **Corruption Recovery**: Repair and analyze damaged SQLite databases
- **Deleted Data Recovery**: Carve data from unallocated database pages
- **Schema Analysis**: Extract table structures from corrupted files
- **Evidence Preservation**: Analyze databases without modifying originals

### 🌐 Network Forensics
- **File Transfer Analysis**: Track FTP uploads/downloads with hash verification
- **HTTP Content Extraction**: Reconstruct downloaded files from PCAP
- **Telnet Session Replay**: Analyze cleartext command execution
- **Protocol Analysis**: Decode custom and proprietary protocols

### 🛡️ Security Monitoring
- **Process Genealogy**: Track parent-child process relationships for threat hunting
- **Suspicious Execution**: Identify unusual process spawns and command lines
- **Web Server Security**: Monitor IIS/Tomcat for exploitation attempts
- **Traffic Anomalies**: Detect unusual bandwidth patterns and port usage

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your plugin or enhancement
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Architecture

```
LogSnoop/
├── logsnoop/
│   ├── __init__.py          # Package initialization
│   ├── core.py              # Main parser engine
│   ├── database.py          # Flat file database
│   └── plugins/
│       ├── __init__.py      # Plugin loader
│       ├── base.py          # Base plugin class
│       ├── ssh_auth.py      # SSH authentication plugin
│       ├── ftp_log.py       # FTP server log plugin
│       ├── http_access.py   # HTTP access log plugin
│       ├── simple_login.py  # Simple login log plugin
│       ├── sky_log.py       # SKY binary log plugin
│       ├── tomcat_log.py    # Apache Tomcat log plugin
│       ├── iis_log.py       # Microsoft IIS log plugin
│       ├── process_tree.py  # Process tree JSON plugin
│       ├── pcap_network.py  # PCAP network traffic plugin (Scapy)
│       ├── emv.py           # EMV payment card transaction plugin
│       └── sqlite_db.py     # SQLite database forensics plugin
├── cli.py                   # Command line interface
├── main.py                  # Entry point
├── setup.py                 # Package setup
├── requirements.txt         # Python dependencies
├── Makefile                 # Build automation
├── install.sh               # Linux/macOS installer
├── install.bat              # Windows installer
└── README.md               # This file
```

## Plugin Capabilities Summary

| Plugin | File Types | Key Features | Query Count |
|--------|-----------|--------------|-------------|
| `ssh_auth` | auth.log, secure | Failed/successful logins, brute force detection | 7 |
| `ftp_log` | vsftpd, proftpd | File transfers, bandwidth tracking | 10 |
| `http_access` | Apache, Nginx | Web traffic, status codes, bandwidth | 10 |
| `simple_login` | Custom text | Login patterns, timeline analysis | 8 |
| `sky_log` | Binary .sky | Network traffic, CAN bus telemetry | 10 |
| `tomcat_log` | Tomcat logs | Java web app errors, sessions | 16 |
| `iis_log` | IIS W3C | Windows web server, ASP.NET | 20 |
| `process_tree` | JSON | Process hierarchy, parent-child relationships | 7 |
| `pcap_network` | .pcap, .pcapng | Network forensics, protocol analysis | 30+ |
| `emv` | EMV logs | Payment card fraud detection | 8 |
| `sqlite_db` | .db | Database forensics, corruption recovery | 7 |

**Total**: 11 plugins, 130+ queries, 10+ file formats supported
