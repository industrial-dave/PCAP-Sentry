PCAP Sentry - Malware Analysis Console

PCAP Sentry analyzes PCAP/PCAPNG files, summarizes traffic statistics,
and provides heuristic signals to help triage suspicious network activity.

Features
- Risk scoring from 0-100 with verdict explanation
- Credential extraction from cleartext protocols
- Host discovery (IPs, MACs, hostnames)
- C2 and data exfiltration detection
- Wireshark filter generation
- Threat intelligence integration (AlienVault OTX, URLhaus)
- Trainable knowledge base with optional ML model
- Local LLM chat interface (Ollama runs offline/local; OpenAI-compatible can be local or cloud)

Installation
Download and run PCAP_Sentry_Setup.exe from the Releases page:
https://github.com/industrial-dave/PCAP-Sentry/releases
Optional: choose Install Ollama and select models to download during setup.

Running from Source
1. Install Python 3.14+
2. Create virtual environment: python -m venv .venv
3. Activate: .venv\Scripts\activate.bat
4. Install dependencies: pip install -r requirements.txt
5. Run: python Python\pcap_sentry_gui.py

Requirements
- Windows 10/11 (64-bit)
- 4 GB RAM minimum (8 GB recommended)
- VC++ Redistributable 2015+ (included with installer)

Support
https://github.com/industrial-dave/PCAP-Sentry/issues
