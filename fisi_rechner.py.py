#!/usr/bin/env python3
"""
FISI All-in-One Terminal-Rechner
================================
- Taschenrechner (sicher, ohne eval)
- Subnetz / IP-Rechner (für FISI Prüfung & Alltag)
- FISI Command-Cheatsheet:
    Windows-Befehle -> PowerShell / Windows Terminal
    Linux-Befehle   -> Bash
    WSL-Befehle     -> Linux-Befehle aufgerufen aus PowerShell / CMD (laut Microsoft-Doku: `wsl <befehl>`)

Start:
  PowerShell / CMD / Bash:
    python fisi_rechner.py --help
    python fisi_rechner.py calc "2+3*4"
    python fisi_rechner.py subnet 192.168.1.10/24
    python fisi_rechner.py cmds --os windows
    python fisi_rechner.py menu
"""

import argparse
import ast
import operator
import ipaddress
import sys
import textwrap

# Windows-Konsole (CMD / alte PowerShell) auf UTF-8 umstellen, sonst kaputte Umlaute
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ---------- Taschenrechner (sicher via AST) ----------

_ALLOWED_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

_ALLOWED_FUNCS = {
    "abs": abs,
    "round": round,
    "min": min,
    "max": max,
    "pow": pow,
}


def safe_calc(expr: str):
    """
    Berechnet einen Ausdruck sicher über AST.
    Erlaubt: + - * / // % ** ( ) und abs/round/min/max/pow
    Beispiel: "2+3*4", "(10-2)/4", "2**8", "10 % 3"
    """
    expr = expr.strip().replace(",", ".").replace("x", "*").replace("×", "*").replace("÷", "/")
    tree = ast.parse(expr, mode="eval")

    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float)):
                return node.value
            raise ValueError(f"Unerlaubter Wert: {node.value!r}")
        if isinstance(node, ast.BinOp):
            op = _ALLOWED_OPS.get(type(node.op))
            if op is None:
                raise ValueError(f"Operator nicht erlaubt: {type(node.op).__name__}")
            return op(_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp):
            op = _ALLOWED_OPS.get(type(node.op))
            if op is None:
                raise ValueError("Unary-Operator nicht erlaubt")
            return op(_eval(node.operand))
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in _ALLOWED_FUNCS:
                raise ValueError("Nur abs(), round(), min(), max(), pow() erlaubt")
            func = _ALLOWED_FUNCS[node.func.id]
            args = [_eval(a) for a in node.args]
            return func(*args)
        raise ValueError(f"Nicht erlaubt: {type(node).__name__}")

    return _eval(tree)


# ---------- Subnetzrechner ----------

def subnet_info(cidr: str) -> dict:
    """
    cidr z.B. "192.168.1.10/24" oder "10.0.0.1/255.255.255.0"
    """
    cidr = cidr.strip()
    # auch "192.168.1.0 255.255.255.0" akzeptieren
    if " " in cidr and "/" not in cidr:
        parts = cidr.split()
        if len(parts) == 2:
            cidr = f"{parts[0]}/{parts[1]}"
    try:
        iface = ipaddress.ip_interface(cidr)
    except ValueError as e:
        raise ValueError(f"Ungültige Eingabe '{cidr}'. Beispiel: 192.168.1.10/24\nDetails: {e}")

    if isinstance(iface.network, ipaddress.IPv4Network):
        net = iface.network
        mask = str(net.netmask)
        wildcard = str(net.hostmask)
        prefix = net.prefixlen
        net_addr = str(net.network_address)
        broadcast = str(net.broadcast_address)
        num_total = net.num_addresses
        num_hosts = max(num_total - 2, 1) if num_total > 2 else (1 if num_total == 2 else 0)
        hosts = list(net.hosts())
        if hosts:
            first = str(hosts[0])
            last = str(hosts[-1])
            host_range = f"{first} - {last}"
        else:
            first = last = host_range = "-"
        ip_class = ip_class_of(str(iface.ip))
        privat = "ja (privat nach RFC1918)" if iface.ip.is_private else "nein (öffentlich)"
        return {
            "Eingabe": cidr,
            "IP": str(iface.ip),
            "Netz": net_addr,
            "Prefix / CIDR": f"/{prefix}",
            "Subnetzmaske": mask,
            "Wildcard": wildcard,
            "Broadcast": broadcast,
            "Host-Range": host_range,
            "Erste Host-IP": first,
            "Letzte Host-IP": last,
            "Adressen gesamt": str(num_total),
            "Nutzbare Hosts": str(num_hosts),
            "IP-Klasse": ip_class,
            "Privat": privat,
            "Binaer Maske": ip_to_bin(mask),
            "Binaer IP": ip_to_bin(str(iface.ip)),
        }
    else:
        # IPv6
        net = iface.network
        return {
            "Eingabe": cidr,
            "IP": str(iface.ip),
            "Netz": str(net.network_address),
            "Prefix / CIDR": f"/{net.prefixlen}",
            "Subnetzmaske": "(IPv6 nutzt nur Präfix)",
            "Adressen gesamt": str(net.num_addresses),
            "Hinweis": "IPv6 hat kein Broadcast, kein Klassen-System",
        }


def ip_class_of(ip_str: str) -> str:
    first = int(ip_str.split(".")[0])
    if 1 <= first <= 126:
        return "A (/8 Standard)"
    if first == 127:
        return "Loopback"
    if 128 <= first <= 191:
        return "B (/16 Standard)"
    if 192 <= first <= 223:
        return "C (/24 Standard)"
    if 224 <= first <= 239:
        return "D (Multicast)"
    return "E (Experimentell)"


def ip_to_bin(ip_str: str) -> str:
    return ".".join(f"{int(o):08b}" for o in ip_str.split("."))


# ---------- FISI Command Cheatsheet ----------
# Regel nach Microsoft-Doku:
# - Windows: PowerShell / Windows Terminal
# - Linux: Bash
# - WSL: Linux-Befehl aufgerufen aus PowerShell/CMD via `wsl <befehl>` , z.B. `wsl ls -la`

COMMANDS = [
    # (Kategorie, Beschreibung, Windows PowerShell, Linux Bash, WSL aus PowerShell/CMD)
    ("Netzwerk", "IP-Adressen anzeigen",
     "Get-NetIPAddress | Format-Table IPAddress, InterfaceAlias  # oder: ipconfig /all",
     "ip a  # oder: ip addr show",
     "wsl ip a"),
    ("Netzwerk", "Routing-Tabelle anzeigen",
     "Get-NetRoute | Format-Table DestinationPrefix, NextHop",
     "ip route show",
     "wsl ip route show"),
    ("Netzwerk", "Ping (4 Pakete)",
     "Test-Connection 8.8.8.8 -Count 4  # klassisch: ping 8.8.8.8 -n 4",
     "ping -c 4 8.8.8.8",
     "wsl ping -c 4 8.8.8.8"),
    ("Netzwerk", "DNS auflösen",
     "Resolve-DnsName google.de  # klassisch: nslookup google.de",
     "nslookup google.de  # oder: dig google.de",
     "wsl dig google.de"),
    ("Netzwerk", "Offene Ports / Verbindungen",
     "Get-NetTCPConnection | Sort-Object State | Format-Table LocalPort, RemoteAddress, State",
     "ss -tuln  # alt: netstat -tuln",
     "wsl ss -tuln"),
    ("Netzwerk", "WLAN-Profile / Passwort (Windows)",
     "netsh wlan show profiles  # Passwort: netsh wlan show profile name=\"WLAN\" key=clear",
     "nmcli device wifi list",
     "— (Hardware-Zugriff nur direkt in Windows, nicht via WSL)"),
    ("Netzwerk", "WSL-Status / Distros (Microsoft-Doku)",
     "wsl --list --verbose  # wsl -l -v",
     "— (nur Windows-Seite)",
     "wsl --status"),
    ("Dateien", "Verzeichnis auflisten",
     "Get-ChildItem  # Alias: ls / dir",
     "ls -la",
     "wsl ls -la"),
    ("Dateien", "Aktueller Pfad",
     "Get-Location  # Alias: pwd",
     "pwd",
     "wsl pwd"),
    ("Dateien", "Verzeichnis wechseln",
     "Set-Location C:\\Temp  # Alias: cd",
     "cd /tmp",
     "wsl cd /tmp (gilt nur in WSL-Session)"),
    ("Dateien", "Datei erstellen / schreiben",
     "\"Hallo\" | Out-File test.txt  # oder: New-Item test.txt",
     "echo Hallo > test.txt",
     "wsl bash -c \"echo Hallo > test.txt\""),
    ("Dateien", "Dateiinhalt anzeigen",
     "Get-Content test.txt  # Alias: cat / type",
     "cat test.txt",
     "wsl cat test.txt"),
    ("Dateien", "Kopieren / Verschieben",
     "Copy-Item a.txt b.txt  # Move-Item a.txt c:\\ziel\\",
     "cp a.txt b.txt  # mv a.txt /ziel/",
     "wsl cp a.txt b.txt"),
    ("Dateien", "Suchen in Dateien",
     "Select-String -Path *.log -Pattern \"Fehler\"  # Alias: sls",
     "grep -R \"Fehler\" .",
     "wsl grep -R \"Fehler\" ."),
    ("System", "Systeminfo",
     "Get-ComputerInfo | Select-Object OsName, OsVersion, CsProcessors  # oder: systeminfo",
     "uname -a  # Details: lsb_release -a / hostnamectl",
     "wsl uname -a"),
    ("System", "Uptime / Laufzeit",
     "(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime",
     "uptime",
     "wsl uptime"),
    ("System", "Festplatte / Speicher",
     "Get-PSDrive C  # oder: Get-Volume",
     "df -h  # RAM: free -h",
     "wsl df -h"),
    ("System", "Prozesse anzeigen",
     "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
     "ps aux --sort=-%cpu | head",
     "wsl ps aux | head"),
    ("System", "Prozess beenden",
     "Stop-Process -Name notepad -Force  # oder: taskkill /IM notepad.exe /F",
     "kill <PID>  # kill -9 <PID>",
     "wsl kill <PID>"),
    ("System", "Dienste verwalten",
     "Get-Service | Where-Object Status -eq Running  # Start: Start-Service wuauserv",
     "systemctl status --no-pager  # sudo systemctl start nginx",
     "— (systemd in WSL je nach Setup, sonst: wsl service nginx status)"),
    ("Benutzer", "Angemeldeter User / Wer bin ich",
     "whoami  # Details: Get-LocalUser",
     "whoami  # Details: id",
     "wsl whoami"),
    ("Benutzer", "Benutzer anlegen",
     "New-LocalUser -Name \"azubi\" -Password (Read-Host -AsSecureString)",
     "sudo useradd -m azubi && sudo passwd azubi",
     "wsl sudo useradd -m azubi"),
    ("Berechtigung", "Rechte anzeigen / setzen",
     "Get-Acl datei.txt | Format-List  # Setzen: icacls datei.txt /grant Benutzer:F",
     "ls -l  # chmod 644 datei.txt  # chown user:gruppe datei.txt",
     "wsl ls -l"),
    ("Pakete", "Software installieren",
     "winget install --id Microsoft.VisualStudioCode  # alt: choco install vscode",
     "sudo apt update && sudo apt install -y htop",
     "wsl sudo apt update && wsl sudo apt install -y htop"),
    ("PowerShell vs Bash", "Hilfe zu Befehl",
     "Get-Help Get-Process  # Alias-Hilfe: Get-Command *net*",
     "man ls  # oder: ls --help",
     "wsl man ls"),
    ("PowerShell vs Bash", "Verlauf / History",
     "Get-History  # Verlauf-Datei: (Get-PSReadLineOption).HistorySavePath",
     "history",
     "wsl history"),
    ("PowerShell vs Bash", "Umgebungsvariablen",
     "Get-ChildItem Env:  # Einzel: $env:PATH",
     "env | sort  # Einzel: echo $PATH",
     "wsl env | sort"),
    ("Netzwerk FISI", "Traceroute",
     "Test-NetConnection google.de -TraceRoute  # klassisch: tracert google.de",
     "traceroute google.de  # oder: tracepath google.de",
     "wsl traceroute google.de"),
    ("Netzwerk FISI", "Port testen",
     "Test-NetConnection 192.168.1.1 -Port 443",
     "nc -vz 192.168.1.1 443  # oder: ss/nmap",
     "wsl nc -vz 192.168.1.1 443"),
]


def print_cmds(filter_os="alle", kategorie=None, suche=None):
    filter_os = filter_os.lower()
    print()
    print("FISI COMMAND CHEATSHEET")
    print("Windows = PowerShell / Windows Terminal | Linux = Bash | WSL = aus PowerShell/CMD via `wsl ...`")
    print("-" * 100)
    count = 0
    last_kat = None
    for kat, beschr, win, lin, wsl_cmd in COMMANDS:
        if kategorie and kategorie.lower() not in kat.lower():
            continue
        if suche and suche.lower() not in (beschr + win + lin + wsl_cmd + kat).lower():
            continue
        if last_kat != kat:
            print(f"\n[{kat}]")
            last_kat = kat
        print(f"  • {beschr}")
        if filter_os in ("alle", "windows", "win", "powershell"):
            print(f"      Windows (PS): {win}")
        if filter_os in ("alle", "linux", "bash"):
            print(f"      Linux (Bash): {lin}")
        if filter_os in ("alle", "wsl"):
            print(f"      WSL in PS/CMD: {wsl_cmd}")
        count += 1
    print("-" * 100)
    print(f"{count} Befehl(e) gefunden. Tipp: `cmds --suche ping` oder `cmds --os wsl`")
    print("Microsoft-Doku Hinweis: In PowerShell/CMD immer `wsl <linux-befehl>` voranstellen, z.B. `wsl ls -la`.")
    print()


# ---------- CLI ----------

def cmd_calc(args):
    try:
        ergebnis = safe_calc(args.ausdruck)
        print(ergebnis)
    except ZeroDivisionError:
        print("Fehler: Division durch 0", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Fehler: {e}", file=sys.stderr)
        sys.exit(2)


def cmd_subnet(args):
    try:
        info = subnet_info(args.cidr)
    except ValueError as e:
        print(f"Fehler: {e}", file=sys.stderr)
        sys.exit(2)
    breite = max(len(k) for k in info)
    print()
    print(f"SUBNETZ-RECHNER  ({info.pop('Eingabe')})")
    print("-" * 50)
    for k, v in info.items():
        print(f"{k:<18}: {v}")
    print("-" * 50)
    print()


def cmd_cmds(args):
    print_cmds(filter_os=args.os, kategorie=args.kategorie, suche=args.suche)


def interactive_menu():
    print(textwrap.dedent("""
    ================================
     FISI All-in-One Terminal-Rechner
    ================================
     [1] Taschenrechner
     [2] Subnetz / IP-Rechner
     [3] FISI Commands (alle)
     [4] FISI Commands (nur Windows/PowerShell)
     [5] FISI Commands (nur Linux/Bash)
     [6] FISI Commands (nur WSL)
     [0] Beenden
    """))
    while True:
        try:
            wahl = input("Auswahl > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nTschüss!")
            break
        if wahl == "1":
            expr = input("Rechnung (z.B. 2+3*4, 2**8, 10%3) > ")
            try:
                print("= ", safe_calc(expr))
            except Exception as e:
                print(f"Fehler: {e}")
        elif wahl == "2":
            cidr = input("IP/CIDR (z.B. 192.168.1.10/24) > ")
            try:
                info = subnet_info(cidr)
                info.pop("Eingabe", None)
                for k, v in info.items():
                    print(f"{k:<18}: {v}")
            except Exception as e:
                print(f"Fehler: {e}")
        elif wahl in ("3", "4", "5", "6"):
            mapping = {"3": "alle", "4": "windows", "5": "linux", "6": "wsl"}
            print_cmds(filter_os=mapping[wahl])
        elif wahl == "0":
            print("Tschüss!")
            break
        else:
            print("Bitte 0-6 wählen (oder STRG+C zum Abbrechen).")


def build_parser():
    p = argparse.ArgumentParser(
        prog="fisi_rechner",
        description="FISI All-in-One Terminal-Rechner: calc + subnet + cmds (PowerShell/Bash/WSL)")
    sub = p.add_subparsers(dest="befehl", required=False)

    pc = sub.add_parser("calc", help="Taschenrechner, z.B. calc \"2+3*4\"")
    pc.add_argument("ausdruck", help="Rechenausdruck in Anführungszeichen, z.B. \"(10-2)/4\"")
    pc.set_defaults(func=cmd_calc)

    ps = sub.add_parser("subnet", help="Subnetzrechner, z.B. subnet 192.168.1.10/24")
    ps.add_argument("cidr", help="IP mit CIDR, z.B. 192.168.1.10/24 oder 10.0.0.1/8")
    ps.set_defaults(func=cmd_subnet)

    pm = sub.add_parser("cmds", help="FISI Command-Cheatsheet anzeigen")
    pm.add_argument("--os", default="alle",
                    help="alle | windows | linux | wsl (Standard: alle)")
    pm.add_argument("--kategorie", default=None,
                    help="Filter, z.B. Netzwerk, Dateien, System")
    pm.add_argument("--suche", default=None,
                    help="Volltextsuche, z.B. --suche ping")
    pm.set_defaults(func=cmd_cmds)

    pm2 = sub.add_parser("menu", help="Interaktives Menü starten")
    pm2.set_defaults(func=lambda a: interactive_menu())

    return p


def main():
    parser = build_parser()
    if len(sys.argv) == 1:
        interactive_menu()
        return
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()