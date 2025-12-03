#!/usr/bin/env python3
"""
Quick test script to verify the scanner works correctly.
Run this after making changes to ensure everything still functions.
"""

import subprocess
import json
import sys

def run_test(description, command, expected_findings=None):
    """Run a test command and check results."""
    print(f"\n{'='*60}")
    print(f"TEST: {description}")
    print(f"{'='*60}")
    print(f"Command: {command}")
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )
        
        print(f"Exit code: {result.returncode}")
        
        if expected_findings is not None:
            # Parse JSON output
            output = json.loads(result.stdout)
            actual = output['summary']['total']
            
            if actual == expected_findings:
                print(f"✓ PASS: Found {actual} secrets (expected {expected_findings})")
                return True
            else:
                print(f"✗ FAIL: Found {actual} secrets (expected {expected_findings})")
                return False
        else:
            print("✓ PASS: Command executed successfully")
            return True
            
    except Exception as e:
        print(f"✗ FAIL: {e}")
        return False

def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("SECRET SCANNER TEST SUITE")
    print("="*60)
    
    tests_passed = 0
    tests_total = 0
    
    # Test 1: Basic scan
    tests_total += 1
    if run_test(
        "Basic file scan",
        "python secret_scanner.py test_samples.py",
        expected_findings=None
    ):
        tests_passed += 1
    
    # Test 2: JSON format output
    tests_total += 1
    if run_test(
        "JSON format output",
        "python secret_scanner.py test_samples.py --format json",
        expected_findings=9
    ):
        tests_passed += 1
    
    # Test 3: JSON file export
    tests_total += 1
    if run_test(
        "JSON file export",
        "python secret_scanner.py test_samples.py --json test_output.json",
        expected_findings=None
    ):
        tests_passed += 1
    
    # Summary
    print(f"\n{'='*60}")
    print(f"TEST SUMMARY")
    print(f"{'='*60}")
    print(f"Passed: {tests_passed}/{tests_total}")
    
    if tests_passed == tests_total:
        print("✓ All tests passed!")
        return 0
    else:
        print(f"✗ {tests_total - tests_passed} test(s) failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
