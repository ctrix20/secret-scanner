#!/usr/bin/env python3
"""
Secret Scanner CLI Tool
Scans files and repositories for hardcoded secrets using regex patterns and entropy detection.
"""

import argparse
from pathlib import Path


class SecretScanner:
    """Main scanner class for detecting secrets in files."""
    
    def __init__(self):
        """Initialize the scanner with directories to skip."""
        # Directories we should skip (common non-code folders)
        self.skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
    
    def scan_directory(self, directory):
        """
        Walk through a directory and scan all files.
        
        Args:
            directory: Path to directory to scan
            
        Returns:
            List of findings (empty for now, we'll add detection later)
        """
        directory = Path(directory)
        
        if not directory.exists():
            print(f"Error: Directory '{directory}' does not exist")
            return []
        
        print(f"Scanning directory: {directory}")
        print("-" * 50)
        
        file_count = 0
        
        # Walk through all files recursively
        for filepath in directory.rglob("*"):
            # Skip if it's a directory
            if filepath.is_dir():
                continue
            
            # Skip if it's in a directory we want to ignore
            if any(skip_dir in filepath.parts for skip_dir in self.skip_dirs):
                continue
            
            # For now, just print the file we're scanning
            print(f"Scanning: {filepath}")
            file_count += 1
        
        print("-" * 50)
        print(f"Scanned {file_count} files")
        
        return []  # We'll return actual findings later


def main():
    """Main entry point for the CLI tool."""
    parser = argparse.ArgumentParser(description='Scan files and directories for hardcoded secrets')
    parser.add_argument('path', help='File or directory to scan')
    args = parser.parse_args()
    
    scanner = SecretScanner()
    findings = scanner.scan_directory(args.path)
    
    print(f"\nFound {len(findings)} potential secrets")


if __name__ == '__main__':
    main()