import os
import subprocess
import sys

def find_vscode_path():
    """Find the VS Code installation path on the system"""
    possible_paths = [
        os.path.expandvars(r'%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe'),
        r'C:\Program Files\Microsoft VS Code\Code.exe',
        r'C:\Program Files (x86)\Microsoft VS Code\Code.exe',
        r'C:\Users\*\AppData\Local\Programs\Microsoft VS Code\Code.exe'
    ]
    
    print("Searching for VS Code installation...")
    
    # Check if 'code' command is available
    try:
        subprocess.run(['code', '--version'], capture_output=True)
        print("VS Code command-line tool is available in PATH")
        return True
    except FileNotFoundError:
        print("VS Code command-line tool not found in PATH")
    
    # Check possible installation paths
    for path in possible_paths:
        if os.path.exists(path):
            print(f"Found VS Code at: {path}")
            return path
    
    print("\nVS Code not found in common installation paths.")
    print("\nTo fix this, you can:")
    print("1. Install VS Code from https://code.visualstudio.com/")
    print("2. Add VS Code to your PATH:")
    print("   a. Open VS Code")
    print("   b. Press Ctrl+Shift+P")
    print("   c. Type 'Shell Command: Install code command in PATH'")
    print("   d. Press Enter")
    print("\nAfter completing these steps, restart your terminal and try again.")
    
    return False

if __name__ == "__main__":
    find_vscode_path() 