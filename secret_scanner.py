#!/usr/bin/env python3
"""
Secret Scanner CLI Tool
Scans files and repositories for hardcoded secrets using regex patterns and entropy detection.
"""

import argparse
import json
import math
import re
from pathlib import Path


class SecretScanner:
    """Main scanner class for detecting secrets in files."""
    
    def __init__(self, min_entropy=4.5):
        """Initialize the scanner with directories to skip."""
        # Directories we should skip (common non-code folders)
        self.skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}
        
        # Minimum entropy threshold for detecting high-entropy strings
        self.min_entropy = min_entropy
        
        # Regex patterns for detecting secrets
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
            'Generic API Key': r'api[_-]?key["\s:=]+["\']?[0-9a-zA-Z]{32,}["\']?',
            'Private Key': r'-----BEGIN .* PRIVATE KEY-----',
        }
        
        # Risk levels for different secret types
        self.risk_levels = {
            'AWS Access Key': 'HIGH',
            'GitHub Token': 'HIGH',
            'Private Key': 'HIGH',
            'Generic API Key': 'MEDIUM',
        }
    
    def calculate_risk(self, finding_type, entropy=None):
        """
        Calculate risk level for a finding.
        
        Risk Criteria:
        - HIGH: Known critical patterns (AWS keys, GitHub tokens, private keys)
                or entropy >= 5.0
        - MEDIUM: Generic API keys or entropy >= 4.5 and < 5.0
        - LOW: Entropy < 4.5
        
        Args:
            finding_type: Type of secret found
            entropy: Entropy value (if applicable)
            
        Returns:
            String: 'HIGH', 'MEDIUM', or 'LOW'
        """
        # Check if it's a known pattern with assigned risk
        if finding_type in self.risk_levels:
            return self.risk_levels[finding_type]
        
        # For high-entropy strings, base risk on entropy value
        if entropy is not None:
            if entropy >= 5.0:
                return 'HIGH'
            elif entropy >= 4.5:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        # Default to medium risk
        return 'MEDIUM'
    
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
                    # Method 1: Check regex patterns
                    for pattern_name, pattern in self.patterns.items():
                        match = re.search(pattern, line)
                        if match:
                            # Found a secret! Save the details
                            risk = self.calculate_risk(pattern_name)
                            findings.append({
                                'type': pattern_name,
                                'risk': risk,
                                'file': str(filepath),
                                'line': line_num,
                                'value': match.group(),
                                'context': line.strip()
                            })
                    
                    # Method 2: Check for high-entropy strings
                    high_entropy = self.find_high_entropy_strings(line)
                    for item in high_entropy:
                        entropy_val = item['entropy']
                        risk = self.calculate_risk('High Entropy String', entropy=entropy_val)
                        findings.append({
                            'type': f'High Entropy String',
                            'risk': risk,
                            'entropy': entropy_val,
                            'file': str(filepath),
                            'line': line_num,
                            'value': item['value'],
                            'context': line.strip()
                        })
        
        except UnicodeDecodeError:
            # Skip binary files (images, executables, etc.)
            pass
        except Exception as e:
            # Skip files we can't read
            print(f"Warning: Could not scan {filepath}: {e}")
        
        return findings
    
    def calculate_entropy(self, string):
        """
        Calculate Shannon entropy of a string.
        Higher entropy = more random/unpredictable.
        
        Args:
            string: The string to analyze
            
        Returns:
            Float representing entropy (0 = not random, 5+ = very random)
        """
        if not string:
            return 0.0
        
        # Count how many times each character appears
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy using Shannon's formula
        entropy = 0.0
        length = len(string)
        
        for count in char_counts.values():
            # Probability of this character
            probability = count / length
            # Add to entropy (negative because log of fraction is negative)
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def find_high_entropy_strings(self, line):
        """
        Find strings in a line that have high entropy (likely secrets).
        
        Args:
            line: Line of text to analyze
            
        Returns:
            List of high-entropy strings found
        """
        high_entropy_strings = []
        
        # Look for quoted strings or long alphanumeric sequences
        # Pattern finds: "text", 'text', or sequences of 20+ alphanumeric chars
        patterns = [
            r'["\']([a-zA-Z0-9+/=_\-]{20,})["\']',  # Quoted strings
            r'(?<![a-zA-Z0-9])([a-zA-Z0-9+/=_\-]{32,})(?![a-zA-Z0-9])',  # Long sequences
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                # Get the actual string (group 1 if it exists, otherwise group 0)
                string = match.group(1) if match.lastindex else match.group(0)
                
                # Calculate entropy
                entropy = self.calculate_entropy(string)
                
                # If entropy is high enough, it might be a secret
                if entropy >= self.min_entropy:
                    high_entropy_strings.append({
                        'value': string,
                        'entropy': entropy
                    })
        
        return high_entropy_strings


def get_risk_color(risk):
    """
    Get ANSI color code for risk level.
    
    Args:
        risk: Risk level string ('HIGH', 'MEDIUM', 'LOW')
        
    Returns:
        ANSI color code string
    """
    colors = {
        'HIGH': '\033[91m',      # Red
        'MEDIUM': '\033[93m',    # Yellow
        'LOW': '\033[92m',       # Green
    }
    reset = '\033[0m'  # Reset color
    
    color = colors.get(risk, '')
    return f"{color}{risk}{reset}"


def main():
    """Main entry point for the CLI tool."""
    parser = argparse.ArgumentParser(description='Scan files and directories for hardcoded secrets')
    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('--json', '-j', metavar='FILE', help='Export results to JSON file')
    parser.add_argument('--format', choices=['text', 'json'], default='text', 
                        help='Output format (default: text)')
    args = parser.parse_args()
    
    scanner = SecretScanner()
    findings = scanner.scan_directory(args.path)
    
    # Count findings by risk level
    risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for finding in findings:
        risk_counts[finding['risk']] += 1
    
    # If JSON format requested, output JSON to stdout
    if args.format == 'json':
        output = {
            'summary': {
                'total': len(findings),
                'high': risk_counts['HIGH'],
                'medium': risk_counts['MEDIUM'],
                'low': risk_counts['LOW']
            },
            'findings': findings
        }
        print(json.dumps(output, indent=2))
    
    # Otherwise, display text format
    else:
        print(f"\n{'='*50}")
        print(f"Found {len(findings)} potential secrets")
        print(f"  HIGH: {risk_counts['HIGH']} | MEDIUM: {risk_counts['MEDIUM']} | LOW: {risk_counts['LOW']}")
        print(f"{'='*50}\n")
        
        # Display each finding
        for finding in findings:
            risk_display = get_risk_color(finding['risk'])
            print(f"[{finding['type']}] - Risk: {risk_display}")
            print(f"  File: {finding['file']}")
            print(f"  Line: {finding['line']}")
            print(f"  Value: {finding['value']}")
            
            # Show entropy if available
            if 'entropy' in finding:
                print(f"  Entropy: {finding['entropy']:.2f}")
            
            print(f"  Context: {finding['context'][:80]}...")  # First 80 chars
            print()
    
    # Save to JSON file if requested
    if args.json:
        output = {
            'summary': {
                'total': len(findings),
                'high': risk_counts['HIGH'],
                'medium': risk_counts['MEDIUM'],
                'low': risk_counts['LOW']
            },
            'findings': findings
        }
        
        with open(args.json, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n✓ Results saved to {args.json}")


if __name__ == '__main__':
    main()