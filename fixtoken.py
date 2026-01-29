#!/usr/bin/env python3
"""
Quick script to test if your WPScan API token is working
"""

import os
import sys
import requests
from colorama import init, Fore, Style

init(autoreset=True)

def test_token(token):
    """Test if token works"""
    if not token:
        return False, "No token provided"
    
    try:
        # Test with WPScan API status endpoint
        url = "https://wpscan.com/api/v3/status"
        headers = {
            "Authorization": f"Token token={token}"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return True, data
        elif response.status_code == 401:
            return False, "Invalid token (401 Unauthorized)"
        elif response.status_code == 429:
            return False, "Rate limit exceeded (429 Too Many Requests)"
        else:
            return False, f"HTTP {response.status_code}: {response.text[:100]}"
    
    except Exception as e:
        return False, f"Error: {str(e)}"

def main():
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  WPScan API Token Checker")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    # Check 1: Environment variable
    env_token = os.environ.get('WPSCAN_API_TOKEN')
    print(f"[1] Environment Variable Check:")
    if env_token:
        print(f"    {Fore.GREEN}✓ WPSCAN_API_TOKEN is set")
        print(f"    Token: {env_token[:10]}...{env_token[-4:]}")
    else:
        print(f"    {Fore.RED}✗ WPSCAN_API_TOKEN not set in environment")
    
    # Check 2: Command line argument
    arg_token = sys.argv[1] if len(sys.argv) > 1 else None
    print(f"\n[2] Command Line Argument:")
    if arg_token:
        print(f"    {Fore.GREEN}✓ Token provided via argument")
        print(f"    Token: {arg_token[:10]}...{arg_token[-4:]}")
    else:
        print(f"    {Fore.YELLOW}⚠ No token provided as argument")
    
    # Determine which token to test
    token_to_test = arg_token or env_token
    
    print(f"\n[3] API Connection Test:")
    if not token_to_test:
        print(f"    {Fore.RED}✗ No token available to test!")
        print(f"\n{Fore.YELLOW}HOW TO FIX:")
        print(f"  Option 1: Set environment variable")
        print(f"    export WPSCAN_API_TOKEN='your_token_here'")
        print(f"\n  Option 2: Pass as argument")
        print(f"    python3 test_token.py your_token_here")
        print(f"\n  Get free token at: {Fore.CYAN}https://wpscan.com/api{Style.RESET_ALL}\n")
        sys.exit(1)
    
    print(f"    Testing token: {token_to_test[:10]}...{token_to_test[-4:]}")
    
    success, result = test_token(token_to_test)
    
    if success:
        print(f"    {Fore.GREEN}✓ Token is VALID!{Style.RESET_ALL}\n")
        print(f"{Fore.WHITE}API Status:")
        print(f"  Plan: {result.get('plan', 'Unknown')}")
        
        requests_info = result.get('requests', {})
        used = requests_info.get('used', 0)
        limit = requests_info.get('limit', 0)
        remaining = requests_info.get('remaining', 0)
        
        print(f"  Requests Used: {used}/{limit}")
        print(f"  Remaining: {Fore.GREEN}{remaining}{Style.RESET_ALL}")
        
        if remaining < 10:
            print(f"\n  {Fore.YELLOW}⚠ Warning: Only {remaining} requests left today!{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}✅ Your token is working correctly!")
        print(f"You can now use it with the scanner:{Style.RESET_ALL}")
        print(f"\n  python3 wp_scan_enhanced.py https://example.com --api-token {token_to_test[:10]}...")
        print(f"  OR")
        print(f"  export WPSCAN_API_TOKEN='{token_to_test[:10]}...'")
        print(f"  python3 wp_scan_enhanced.py https://example.com\n")
    else:
        print(f"    {Fore.RED}✗ Token test FAILED!{Style.RESET_ALL}")
        print(f"    Reason: {result}\n")
        print(f"{Fore.YELLOW}TROUBLESHOOTING:")
        print(f"  1. Check if token is correct (copy from https://wpscan.com/profile)")
        print(f"  2. Make sure no extra spaces or quotes")
        print(f"  3. Try regenerating token on WPScan website")
        print(f"  4. Check internet connection{Style.RESET_ALL}\n")
        sys.exit(1)

if __name__ == '__main__':
    main()
