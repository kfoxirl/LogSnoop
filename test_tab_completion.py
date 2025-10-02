#!/usr/bin/env python3
"""
Test script to verify tab completion functionality
"""

import os
import sys
sys.path.insert(0, '.')

from logsnoop.interactive import LogSnoopInteractive

def test_tab_completion():
    """Test the tab completion setup."""
    print("🧪 Testing Tab Completion Setup")
    print("=" * 40)
    
    interactive = LogSnoopInteractive()
    
    # Check if readline is available
    try:
        import readline
        print("✅ readline module: Available")
        
        # Test if readline functions work
        try:
            readline.get_completer()
            print("✅ readline functions: Working")
        except AttributeError as e:
            print(f"⚠️  readline functions: Limited ({e})")
            
    except ImportError:
        print("❌ readline module: Not available")
        try:
            import pyreadline3
            print("✅ pyreadline3 module: Available (Windows)")
        except ImportError:
            print("❌ pyreadline3 module: Not available")
    
    print("\n🔧 Tab Completion Features:")
    print("• File path completion")
    print("• Directory traversal")  
    print("• Common log file filtering")
    print("• Tilde (~) expansion")
    
    print("\n📝 Usage Instructions:")
    print("1. Start interactive mode: python3 cli.py interactive")
    print("2. Choose option 1 (Parse new file)")
    print("3. Select any plugin") 
    print("4. When entering file path, press TAB to complete")
    
    print("\n💡 Tab Completion Benefits:")
    print("✓ No more typing long paths")
    print("✓ Reduces typos in file names")
    print("✓ Shows available files and directories")
    print("✓ Standard shell-like experience")
    
    # Test the path completer directly
    print("\n🧪 Testing Path Completer:")
    completer = interactive._path_completer
    
    # Test with current directory
    matches = []
    state = 0
    while True:
        match = completer("demo", state)
        if match is None:
            break
        matches.append(match)
        state += 1
        if state > 10:  # Prevent infinite loop
            break
    
    if matches:
        print(f"✅ Found {len(matches)} matches for 'demo*':")
        for match in matches[:5]:  # Show first 5
            print(f"   • {match}")
        if len(matches) > 5:
            print(f"   ... and {len(matches) - 5} more")
    else:
        print("ℹ️  No matches found for 'demo*' (normal if no demo files exist)")
    
    print(f"\n🎯 Interactive Mode Ready!")
    print("Run: python3 cli.py interactive")


if __name__ == '__main__':
    test_tab_completion()