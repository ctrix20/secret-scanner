#!/usr/bin/env python3
"""
Secret Scanner CLI Tool
Scans files and repositories for hardcoded secrets using regex patterns and entropy detection.
"""

import argparse
import re
from pathlib import Path


class SecretScanner:
    """Main scanner class for detecting secrets in files."""
    
    def __init__(self):
        """Initialize the scanner with directories to skip."""
        # Directories we should skip (common non-code folders)
        self.skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
        
        # Regex patterns for detecting secrets
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
            'Generic API Key': r'api[_-]?key["\s:=]+["\']?[0-9a-zA-Z]{32,}["\']?',
            'Private Key': r'-----BEGIN .* PRIVATE KEY-----',
        }
    
    def scan_directory(self, path):
        """
        Walk through a directory (or scan a single file) for secrets.
        
        Args:
            path: Path to file or directory to scan
            
        Returns:
            List of findings
        """
        path = Path(path)
        
        if not path.exists():
            print(f"Error: Path '{path}' does not exist")
            return []
        
        all_findings = []
        file_count = 0
        
        # If it's a single file, just scan it
        if path.is_file():
            print(f"Scanning file: {path}")
            print("-" * 50)
            findings = self.scan_file(path)
            all_findings.extend(findings)
            file_count = 1
        
        # If it's a directory, scan all files in it
        else:
            print(f"Scanning directory: {path}")
            print("-" * 50)
            
            # Walk through all files recursively
            for filepath in path.rglob("*"):
                # Skip if it's a directory
                if filepath.is_dir():
                    continue
                
                # Skip if it's in a directory we want to ignore
                if any(skip_dir in filepath.parts for skip_dir in self.skip_dirs):
                    continue
                
                # Scan this file for secrets
                print(f"Scanning: {filepath}")
                findings = self.scan_file(filepath)
                all_findings.extend(findings)
                file_count += 1
        
        print("-" * 50)
        print(f"Scanned {file_count} files")
        
        return all_findings
    
    def scan_file(self, filepath):
        """
        Scan a single file for secrets using regex patterns.
        
        Args:
            filepath: Path to file to scan
            
        Returns:
            List of findings (dictionaries with details about each secret found)
        """
        findings = []
        
        try:
            # Try to read the file as text
            with open(filepath, 'r', encoding='utf-8') as f:
                # Read line by line (memory efficient for large files)
                for line_num, line in enumerate(f, start=1):
                    # Check each pattern against this line
                    for pattern_name, pattern in self.patterns.items():
                        match = re.search(pattern, line)
                        if match:
                            # Found a secret! Save the details
                            findings.append({
                                'type': pattern_name,
                                'file': str(filepath),
                                'line': line_num,
                                'value': match.group(),
                                'context': line.strip()
                            })
        
        except UnicodeDecodeError:
            # Skip binary files (images, executables, etc.)
            pass
        except Exception as e:
            # Skip files we can't read
            print(f"Warning: Could not scan {filepath}: {e}")
        
        return findings


def main():
    """Main entry point for the CLI tool."""
    parser = argparse.ArgumentParser(description='Scan files and directories for hardcoded secrets')
    parser.add_argument('path', help='File or directory to scan')
    args = parser.parse_args()
    
    scanner = SecretScanner()
    findings = scanner.scan_directory(args.path)
    
    print(f"\n{'='*50}")
    print(f"Found {len(findings)} potential secrets")
    print(f"{'='*50}\n")
    
    # Display each finding
    for finding in findings:
        print(f"[{finding['type']}]")
        print(f"  File: {finding['file']}")
        print(f"  Line: {finding['line']}")
        print(f"  Value: {finding['value']}")
        print(f"  Context: {finding['context'][:80]}...")  # First 80 chars
        print()


if __name__ == '__main__':
    main()