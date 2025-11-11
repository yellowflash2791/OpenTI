OpenTI is a small, open-source threat-intel collector that fetches known-malicious / blacklisted IPs, domains and URLs and stores them locally so you can export them to CSV and feed them into your SIEM, firewalls, IDS, network appliances, or other tooling.

Features

Collects malicious IP addresses, domains and URLs from configured sources.

Stores everything in a local SQLite database (TI.db) for easy local management.

Lightweight web GUI for browsing results and exporting to CSV.

Single-machine friendly: runs with Python and zero external DB dependency.
