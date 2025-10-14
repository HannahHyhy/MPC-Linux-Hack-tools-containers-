#!/usr/bin/env python3
"""
Simple SecTools MCP Server - Educational security testing tools for your own infrastructure
"""
import os
import sys
import logging
import subprocess
import re
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("sectools-server")

# Initialize MCP server
mcp = FastMCP("sectools")

# Configuration
MAX_TIMEOUT = 300  # 5 minutes max for any operation
MAX_OUTPUT_LENGTH = 10000  # Limit output to prevent overwhelming responses

# === UTILITY FUNCTIONS ===

def sanitize_input(input_str: str) -> str:
    """Remove potentially dangerous characters from input."""
    if not input_str:
        return ""
    # Remove shell metacharacters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    sanitized = input_str
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    return sanitized.strip()

def validate_target(target: str) -> str:
    """Validate target is an IP or domain, not a command."""
    if not target:
        return "Target cannot be empty"
    
    # Basic validation for IP or domain
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-_.]+[a-zA-Z0-9]$'
    
    if re.match(ip_pattern, target) or re.match(domain_pattern, target):
        return ""
    return "Invalid target format. Use IP address or domain name only."

def run_command(cmd_list: list, timeout: int = 60) -> str:
    """Execute command safely and return formatted output."""
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout if result.returncode == 0 else result.stderr
        
        # Truncate if too long
        if len(output) > MAX_OUTPUT_LENGTH:
            output = output[:MAX_OUTPUT_LENGTH] + f"\n\n... (output truncated, {len(output) - MAX_OUTPUT_LENGTH} chars omitted)"
        
        return output
        
    except subprocess.TimeoutExpired:
        return f" Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"Command execution error: {e}")
        return f" Execution error: {str(e)}"

# === MCP TOOLS ===

@mcp.tool()
async def nmap_scan(target: str = "", scan_type: str = "quick") -> str:
    """Perform network scan on target using nmap with various scan types: quick, full, service, or vuln."""
    target = sanitize_input(target)
    validation_error = validate_target(target)
    if validation_error:
        return f" {validation_error}"
    
    logger.info(f"Running nmap scan on {target} with type {scan_type}")
    
    scan_options = {
        "quick": ["-T4", "-F"],
        "full": ["-T4", "-p-"],
        "service": ["-sV", "-T4"],
        "vuln": ["--script=vuln", "-T4"]
    }
    
    options = scan_options.get(scan_type, ["-T4", "-F"])
    cmd = ["nmap"] + options + [target]
    
    output = run_command(cmd, timeout=MAX_TIMEOUT)
    return f" Nmap Scan Results for {target}:\n\n{output}"

@mcp.tool()
async def nikto_scan(target: str = "", port: str = "80") -> str:
    """Scan web server for vulnerabilities using Nikto on specified target and port."""
    target = sanitize_input(target)
    port = sanitize_input(port)
    
    validation_error = validate_target(target)
    if validation_error:
        return f" {validation_error}"
    
    try:
        port_num = int(port) if port else 80
        if port_num < 1 or port_num > 65535:
            return " Port must be between 1 and 65535"
    except ValueError:
        return f" Invalid port number: {port}"
    
    logger.info(f"Running nikto scan on {target}:{port_num}")
    
    cmd = ["nikto", "-h", f"{target}:{port_num}", "-Format", "txt"]
    output = run_command(cmd, timeout=MAX_TIMEOUT)
    
    return f" Nikto Web Scan Results for {target}:{port_num}:\n\n{output}"

@mcp.tool()
async def sqlmap_test(target_url: str = "", test_parameter: str = "") -> str:
    """Test URL parameter for SQL injection vulnerabilities using sqlmap with basic detection."""
    target_url = sanitize_input(target_url)
    test_parameter = sanitize_input(test_parameter)
    
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        return " Target URL must start with http:// or https://"
    
    logger.info(f"Running sqlmap test on {target_url}")
    
    cmd = ["sqlmap", "-u", target_url, "--batch", "--level=1", "--risk=1"]
    if test_parameter:
        cmd.extend(["-p", test_parameter])
    
    output = run_command(cmd, timeout=MAX_TIMEOUT)
    return f" SQLMap Test Results for {target_url}:\n\n{output}"

@mcp.tool()
async def wpscan_scan(target: str = "", enumerate: str = "vp") -> str:
    """Scan WordPress site for vulnerabilities using WPScan, enumerate options: vp (vulnerable plugins), vt (vulnerable themes), u (users), or all."""
    target = sanitize_input(target)
    enumerate = sanitize_input(enumerate)
    
    if not target.startswith("http://") and not target.startswith("https://"):
        return " Target must start with http:// or https://"
    
    valid_enums = ["vp", "vt", "u", "all"]
    if enumerate not in valid_enums:
        enumerate = "vp"
    
    logger.info(f"Running wpscan on {target}")
    
    cmd = ["wpscan", "--url", target, "--enumerate", enumerate, "--format", "cli"]
    output = run_command(cmd, timeout=MAX_TIMEOUT)
    
    return f" WPScan Results for {target}:\n\n{output}"

@mcp.tool()
async def dirb_scan(target: str = "", wordlist: str = "common") -> str:
    """Scan web server for hidden directories using dirb with common or big wordlist."""
    target = sanitize_input(target)
    
    if not target.startswith("http://") and not target.startswith("https://"):
        return " Target must start with http:// or https://"
    
    wordlists = {
        "common": "/usr/share/dirb/wordlists/common.txt",
        "big": "/usr/share/dirb/wordlists/big.txt"
    }
    
    wordlist_path = wordlists.get(wordlist, wordlists["common"])
    
    logger.info(f"Running dirb scan on {target}")
    
    cmd = ["dirb", target, wordlist_path, "-S", "-w"]
    output = run_command(cmd, timeout=MAX_TIMEOUT)
    
    return f" Dirb Directory Scan Results for {target}:\n\n{output}"

@mcp.tool()
async def searchsploit_lookup(search_term: str = "") -> str:
    """Search exploitdb database for exploits matching the search term."""
    search_term = sanitize_input(search_term)
    
    if not search_term:
        return " Search term cannot be empty"
    
    logger.info(f"Searching exploitdb for {search_term}")
    
    cmd = ["searchsploit", search_term]
    output = run_command(cmd, timeout=30)
    
    return f" ExploitDB Search Results for '{search_term}':\n\n{output}"

@mcp.tool()
async def port_scan_basic(target: str = "", ports: str = "1-1000") -> str:
    """Quick TCP port scan using nmap on specified port range."""
    target = sanitize_input(target)
    ports = sanitize_input(ports)
    
    validation_error = validate_target(target)
    if validation_error:
        return f" {validation_error}"
    
    logger.info(f"Running basic port scan on {target} ports {ports}")
    
    cmd = ["nmap", "-p", ports, "-T4", "--open", target]
    output = run_command(cmd, timeout=120)
    
    return f" Port Scan Results for {target}:\n\n{output}"

@mcp.tool()
async def get_tool_info() -> str:
    """Get information about available security testing tools and their versions."""
    logger.info("Retrieving tool information")
    
    tools = {
        "nmap": ["nmap", "--version"],
        "nikto": ["nikto", "-Version"],
        "sqlmap": ["sqlmap", "--version"],
        "wpscan": ["wpscan", "--version"],
        "dirb": ["dirb"],
        "searchsploit": ["searchsploit", "-h"]
    }
    
    info = " Available Security Tools:\n\n"
    
    for tool_name, cmd in tools.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            version_info = (result.stdout + result.stderr).split('\n')[0]
            info += f" {tool_name}: {version_info}\n"
        except Exception as e:
            info += f" {tool_name}: Error retrieving info\n"
    
    info += "\n WARNING: These tools are for educational purposes only. Only scan systems you own or have explicit permission to test."
    
    return info

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting SecTools MCP server...")
    logger.info(" Educational security testing tools loaded")
    logger.info(" Only use on systems you own or have permission to test")
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)