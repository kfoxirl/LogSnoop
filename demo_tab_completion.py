#!/usr/bin/env python3
"""
Demo: Tab Completion in LogSnoop Interactive Mode
This script demonstrates the new tab completion functionality.
"""

import os
import sys
from pathlib import Path

def create_demo_structure():
    """Create a demo directory structure to showcase tab completion."""
    demo_paths = [
        "demo_logs/web_servers/apache/access.log",
        "demo_logs/web_servers/nginx/error.log", 
        "demo_logs/auth/ssh_attempts.log",
        "demo_logs/auth/login_records.log",
        "demo_logs/network/traffic_analysis.sky",
        "demo_logs/ftp/transfers.log",
        "sample_data/test.txt",
        "config/settings.conf"
    ]
    
    print("🏗️  Creating demo directory structure for tab completion...")
    
    for path in demo_paths:
        full_path = Path(path)
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create sample content based on file type
        if path.endswith('.log'):
            if 'apache' in path or 'nginx' in path:
                content = '192.168.1.100 - - [02/Oct/2025:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 1024'
            elif 'ssh' in path or 'auth' in path:
                content = 'Oct  2 10:15:23 server sshd[12345]: Failed password for admin from 192.168.1.100'
            elif 'ftp' in path:
                content = 'Oct  2 10:15:23 upload user@192.168.1.100 file.txt 1024 bytes'
            else:
                content = 'Sample log entry for demonstration'
        elif path.endswith('.sky'):
            content = 'Binary network traffic data (simulated)'
        else:
            content = 'Sample configuration data'
            
        full_path.write_text(content)
    
    return demo_paths

def print_demo_instructions():
    """Print instructions for testing tab completion."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                 Tab Completion Demo for LogSnoop                 ║
║                   Interactive Mode Enhancement                   ║
╚══════════════════════════════════════════════════════════════════╝

🎯 NEW FEATURE: Tab Completion for File Paths

When entering file paths in interactive mode, you can now use TAB to:
✅ Auto-complete directory names
✅ Show available files and folders  
✅ Navigate through directory structures
✅ Filter to show common log file types
✅ Expand ~ for home directory

═══════════════════════════════════════════════════════════════════

📋 HOW TO TEST:

1. Start Interactive Mode:
   python3 cli.py interactive

2. Choose "1. Parse a new log file"

3. Select any plugin (e.g., "http_access")

4. When prompted for file path, try these:

   💡 Type "demo" and press TAB
   → Should complete to "demo_logs/"

   💡 Type "demo_logs/" and press TAB  
   → Should show available subdirectories

   💡 Type "demo_logs/web" and press TAB
   → Should complete to "demo_logs/web_servers/"

   💡 Type "demo_logs/web_servers/apache/" and press TAB
   → Should show "access.log"

═══════════════════════════════════════════════════════════════════

🔧 TECHNICAL DETAILS:

Cross-Platform Support:
• Linux/Mac: Uses built-in readline module
• Windows: Uses pyreadline3 (auto-installed)
• Fallback: Regular input if readline unavailable

Smart Filtering:
• Prioritizes common log extensions (.log, .txt, .out)
• Shows directories with trailing slash
• Handles relative and absolute paths
• Supports tilde (~) expansion

Integration:
• Only active during file path input
• Doesn't interfere with other prompts
• Preserves existing functionality
• Zero breaking changes

═══════════════════════════════════════════════════════════════════

🚀 BENEFITS:

User Experience:
• 🚀 Faster file selection
• ❌ Fewer typing errors  
• 💡 Discover available files
• 🎯 Standard shell behavior

Productivity:
• ⚡ Quick navigation through log directories
• 🔍 Easy exploration of file structures
• ✅ Validation through completion
• 🎨 Professional tool experience

═══════════════════════════════════════════════════════════════════

""")

def main():
    """Main demo function."""
    print("Setting up tab completion demo environment...")
    
    # Create demo directory structure
    created_paths = create_demo_structure()
    
    print(f"\n✅ Created {len(created_paths)} demo files and directories:")
    for path in created_paths[:5]:  # Show first 5
        print(f"   📄 {path}")
    if len(created_paths) > 5:
        print(f"   ... and {len(created_paths) - 5} more")
    
    print_demo_instructions()
    
    # Offer to start interactive mode
    try:
        response = input("🚀 Start interactive mode now to test tab completion? (y/n): ").strip().lower()
        if response == 'y':
            print("\n🎯 Launching LogSnoop Interactive Mode...")
            print("💡 Remember to press TAB when entering file paths!")
            os.system(f"{sys.executable} cli.py interactive")
        else:
            print("\n💡 You can test later with: python3 cli.py interactive")
            
    except KeyboardInterrupt:
        print("\n\n👋 Demo completed!")

if __name__ == '__main__':
    main()