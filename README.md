# Scanner de Vulnérabilités Web Automatisé (Intruder)

## Sujet
Développer un scanner de sécurité web capable de détecter automatiquement plusieurs catégories de vulnérabilités au sein d’une application.

## Philosophy
This project is "smart" not because the core code itself is inherently special, but because it orchestrates and combines **special tools** to do something beautiful. 

It acts as a unified localized dashboard (Jarvis) that leverages the power of industry-standard reconnaissance tools to provide an automated, streamlined security analysis workflow.

## Tools Integrated
- **Subfinder**: Subdomain discovery.
- **Nmap**: Port scanning and service detection.
- **Wafw00f**: Web Application Firewall detection ("The Bouncer").
- **Wappalyzer**: Technology stack identification.

## Project Structure
- **/app**: Flask application source code.
- **/scans**: Output directory for scan results.
- **Worker**: Celery + Redis for asynchronous background scanning.
- **Frontend**: Real-time updates via SocketIO with a cyberpunk/dark interface.

---
*Built for the "Red Badge" usage.*
