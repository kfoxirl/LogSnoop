# Installing LogSnoop on Kali Linux

## Method 1: Direct Git Clone (Recommended)

### Prerequisites
```bash
# Update package list
sudo apt update

# Install Python 3 and pip if not already installed
sudo apt install python3 python3-pip python3-venv git -y
```

### Installation Steps
```bash
# 1. Clone the repository
git clone https://github.com/kfoxirl/LogSnoop.git
cd LogSnoop

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Test installation
python3 cli.py --help

# 5. Try interactive mode
python3 cli.py interactive
```

### Make it System-wide (Optional)
```bash
# Install system-wide for easy access
sudo ./install.sh

# Now you can use from anywhere:
logsnoop --help
logsnoop interactive
```

---

## Method 2: Download ZIP and Install

### If you prefer not to use git:
```bash
# 1. Download ZIP from GitHub
wget https://github.com/kfoxirl/LogSnoop/archive/refs/heads/main.zip

# 2. Extract
unzip main.zip
cd LogSnoop-main

# 3. Follow same steps as Method 1 (create venv, install deps, etc.)
```

---

## Method 3: Development Setup

### For contributing or modifying code:
```bash
# 1. Fork the repository on GitHub first
# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/LogSnoop.git
cd LogSnoop

# 3. Set up development environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 4. Add upstream remote
git remote add upstream https://github.com/kfoxirl/LogSnoop.git

# 5. Test everything works
python3 cli.py list-plugins
```

---

## Method 4: Quick Test with Sample Data

### To test immediately with demo data:
```bash
# After installation, create test data
python3 demo_interactive.py
# Choose 'y' to create demo files

# Test parsing
python3 cli.py parse demo_logs/demo_ssh.log ssh_auth

# Test interactive mode
python3 cli.py interactive
```

---

## Common Kali-Specific Notes

### 1. **Virtual Environment Best Practice**
```bash
# Always use virtual environment to avoid conflicts
python3 -m venv .venv
source .venv/bin/activate
```

### 2. **System Integration** 
```bash
# Add to PATH for easy access (optional)
echo 'export PATH="$PATH:/path/to/LogSnoop"' >> ~/.bashrc
source ~/.bashrc
```

### 3. **Log File Locations in Kali**
```bash
# Common log locations to analyze:
/var/log/auth.log          # SSH authentication
/var/log/apache2/access.log # Apache web server  
/var/log/nginx/access.log   # Nginx web server
/var/log/vsftpd.log        # FTP server logs
/var/log/syslog            # System logs
```

### 4. **Permissions for Log Files**
```bash
# You may need sudo to read some log files
sudo python3 cli.py parse /var/log/auth.log ssh_auth

# Or copy logs to user directory first
sudo cp /var/log/auth.log ~/logs/
python3 cli.py parse ~/logs/auth.log ssh_auth
```

---

## Quick Start Commands for Kali

### After installation, try these common Kali log analysis tasks:

```bash
# Analyze SSH authentication attempts
sudo python3 cli.py parse /var/log/auth.log ssh_auth
python3 cli.py query ssh_auth failed_logins

# Check web server access patterns
sudo python3 cli.py parse /var/log/apache2/access.log http_access  
python3 cli.py query http_access requests_by_ip

# Interactive mode for guided analysis
python3 cli.py interactive
```

---

## Troubleshooting

### Common Issues:

1. **Permission denied on log files**
   ```bash
   # Solution: Use sudo or copy files
   sudo cp /var/log/auth.log ~/
   python3 cli.py parse ~/auth.log ssh_auth
   ```

2. **Python module not found**
   ```bash
   # Solution: Activate virtual environment
   source .venv/bin/activate
   ```

3. **Git not installed**
   ```bash
   # Solution: Install git
   sudo apt install git -y
   ```

4. **Pip not found**
   ```bash
   # Solution: Install pip
   sudo apt install python3-pip -y
   ```

### Support
- Check the README.md for detailed usage
- Run `python3 cli.py --help` for command reference  
- Use `python3 cli.py interactive` for guided workflows
- Create issues on GitHub for bugs or questions

---

## Security Notes for Kali Users

- **Log Analysis**: Perfect for forensics and incident response
- **Network Traffic**: Use sky_log plugin for network analysis
- **Web Security**: Tomcat and IIS plugins for web server security analysis  
- **SSH Analysis**: Identify brute force attempts and successful compromises
- **Safe Environment**: Uses read-only log analysis, no system modifications