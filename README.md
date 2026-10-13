# FISI All-in-One Terminal-Rechner

Ein Terminal-Werkzeug für Fachinformatiker für Systemintegration (FISI) und Anwendungsentwicklung:
- **Taschenrechner**: Sicherer Parser ohne `eval()`
- **Subnetz-/IP-Rechner**: Berechnung von CIDR, Host-Range, Wildcard, Netzklassen und Binärdarstellung
- **Command-Cheatsheet**: Wichtige Befehle im Vergleich (PowerShell vs. Linux Bash vs. WSL)

## Nutzung
```bash
python fisi_rechner.py menu
python fisi_rechner.py calc "2+3*4"
python fisi_rechner.py subnet 192.168.1.10/24
python fisi_rechner.py cmds --os windows
