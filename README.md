# brutEX.Sv1.2

Enhanced Vulnerability Assessment Tool
Overview
This tool automates vulnerability scanning, brute-force attacks, and exploits for various web services and protocols (e.g., FTP, SSH, SQL Injection). It is designed to be user-friendly and highly efficient with error handling, multithreading, and automation.

Features
Reconnaissance: Performs DNS and port scanning.
Brute-Force Attacks: Automates brute-force on FTP, SSH, and HTTP.
Exploitation: Automates SQL injection and XSS attacks.
Reporting: Generates detailed attack reports in JSON format with visual graphs.
Tool Availability Check: Ensures required tools (e.g., hydra, sqlmap) are installed.
Multithreading: Uses concurrency to perform tasks efficiently.
Requirements
Python 3.6+
Required libraries:
requests
validators
flask
colorama
plotly
Usage
Install required dependencies:
bash
Copy code
pip install -r requirements.txt
Run the tool:
bash
Copy code
python full_corrected_script.py
Follow the interactive prompts to start a scan or brute-force attack.

Future Enhancements
Add support for more protocols (e.g., RDP, Telnet).
Integrate machine learning to improve anomaly detection.
Add more visualization options for reports.
Include CAPTCHA handling in brute-force attacks.
Enhance error handling for remote network scans.
Why this tool?
This tool is designed with both efficiency and automation in mind. It integrates seamlessly with CI/CD pipelines and is modular for easy expansion. Its user-friendly CLI ensures that even beginners can perform complex vulnerability scans with minimal effort.
