#!/usr/bin/env python3
#tags = ["core_approved", "http", "web"]
#developer = ["Phobos Team", "https://github.com/ibrahmsql/phobos"]
#trigger_port = "80,443,8080,8000,8443"
#call_format = "python3 {{script}} {{ip}} {{port}}"
#description = "HTTP title and header grabber"

"""
Phobos HTTP Title Grabber Script
Extracts HTTP titles and server headers from web services
"""

import sys
import socket
import ssl

def grab_http_info(ip, port):
    """Grab HTTP title and headers"""
    try:
        port = int(port)
        is_ssl = port in [443, 8443]
        
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        
        if is_ssl:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=ip)
        
        sock.connect((ip, port))
        
        # Send HTTP request
        request = f"GET / HTTP/1.1\\r\\nHost: {ip}\\r\\nUser-Agent: Phobos/1.0\\r\\nConnection: close\\r\\n\\r\\n"
        sock.sendall(request.encode())
        
        # Receive response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"</title>" in response.lower():
                break
        
        resp_str = response.decode('utf-8', errors='ignore')
        
        # Extract title
        if '<title>' in resp_str.lower():
            start = resp_str.lower().find('<title>') + 7
            end = resp_str.lower().find('</title>')
            title = resp_str[start:end].strip()
            print(f"[+] Title: {title}")
        
        # Extract server header
        for line in resp_str.split('\\n'):
            if line.lower().startswith('server:'):
                print(f"[+] {line.strip()}")
            if line.lower().startswith('x-powered-by:'):
                print(f"[+] {line.strip()}")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: http_grabber.py <ip> <port>")
        sys.exit(1)
    
    ip = sys.argv[1]
    port = sys.argv[2]
    
    print(f"[*] Scanning {ip}:{port}")
    grab_http_info(ip, port)
