#!/bin/bash
#tags = ["core_approved", "ssh", "banner"]
#developer = ["Phobos Team", "https://github.com/ibrahmsql/phobos"]  
#trigger_port = "22"
#call_format = "bash {{script}} {{ip}} {{port}}"
#description = "SSH banner grabber"

# Phobos SSH Banner Grabber
# Extracts SSH version and banner information

IP=$1
PORT=$2

echo "[*] Grabbing SSH banner from $IP:$PORT"

# Use timeout and netcat to grab banner
BANNER=$(timeout 3 nc -w 2 $IP $PORT 2>/dev/null | head -1)

if [ -n "$BANNER" ]; then
    echo "[+] SSH Banner: $BANNER"
    
    # Parse SSH version
    if [[ $BANNER == *"SSH"* ]]; then
        VERSION=$(echo $BANNER | grep -oP 'SSH-[0-9]\.[0-9]')
        echo "[+] Protocol: $VERSION"
        
        # Extract server type
        if [[ $BANNER == *"OpenSSH"* ]]; then
            echo "[+] Server: OpenSSH"
        elif [[ $BANNER == *"dropbear"* ]]; then
            echo "[+] Server: Dropbear"
        fi
    fi
else
    echo "[-] No banner received"
fi
