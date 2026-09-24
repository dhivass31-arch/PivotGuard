# 🛡️ PivotGuard – Pivoting & Lateral Movement Detection System

PivotGuard is a defensive cybersecurity monitoring and detection system developed to identify suspicious patterns associated with pivoting and lateral movement within a network. The system analyzes network security logs and detects indicators such as a single source system communicating with multiple internal hosts, usage of remote services such as SMB, RDP, SSH and WinRM, multiple remote services accessed by the same source, high connection activity and multiple destination ports. Detected activities are classified into High, Medium and Low risk levels and presented through a professional SOC-style dashboard.

The system provides a centralized dashboard for security monitoring, alert management, network activity analysis, attack-path visualization and security reporting. Analysts can upload CSV-based network logs using the required fields timestamp, source_ip, destination_ip, port and protocol. PivotGuard processes the logs through its detection engine and generates security alerts with timestamp, source IP, destination IP, port, protocol, severity and detection reason.

The project also includes an alert investigation workflow where detected events can be managed through the stages New, Acknowledged, Investigating and Resolved. SQLite is used for storing security events, while Flask provides the web application backend. HTML, CSS and JavaScript are used to create the interactive security dashboard, and Gunicorn is used as the production web server. The application is deployed publicly using Render.

## Key Features

- Pivoting and lateral movement detection
- Network log analysis
- CSV security log upload
- SMB, RDP, SSH, RPC, NetBIOS and WinRM detection
- High, Medium and Low risk classification
- SOC-style security dashboard
- Alert investigation workflow
- Source and destination IP analysis
- Remote service statistics
- Attack-path visualization
- Security report generation
- SQLite event database
- Authentication-protected dashboard
- Cloud deployment using Render

## Detection Logic

PivotGuard identifies suspicious activity using multiple defensive indicators:

1. A source IP communicating with multiple internal destinations.
2. Connections to commonly used remote administration services.
3. Multiple remote services being used by the same source.
4. High connection volume from a single source.
5. Multiple destination ports associated with the same source.

These indicators are combined to classify the observed activity and provide security analysts with useful investigation evidence.

## Technology Stack

- Python
- Flask
- HTML5
- CSS3
- JavaScript
- SQLite
- CSV
- Gunicorn
- Git
- GitHub
- Render

## Project Architecture

Network Security Logs → Log Analysis → Detection Engine → Suspicious Activity Detection → Risk Classification → SQLite Database → PivotGuard Dashboard → Security Investigation & Reporting

## Project Structure

PivotGuard/
├── app.py
├── auth.py
├── database.py
├── detector.py
├── report.py
├── requirements.txt
├── templates/
│   ├── index.html
│   ├── login.html
│   └── monitoring.html
├── static/
│   ├── style.css
│   └── script.js
└── README.md

## Live Demo

https://pivotguard.onrender.com

## Objective

The main objective of PivotGuard is to demonstrate how defensive security monitoring can be used to identify potential lateral movement patterns from network telemetry and present the findings in a centralized SOC-style interface.

## Future Enhancements

Future versions can include real-time log ingestion, SIEM integration, machine-learning-based anomaly detection, Active Directory log analysis, Windows Event Log integration, advanced threat intelligence and persistent cloud databases.

## Ethical Use

PivotGuard is an educational and defensive cybersecurity project. It uses sample or authorized network data for detection and analysis. It does not perform unauthorized access, exploitation or actual lateral movement.

## Author

S. Dhivaakar  
B.Sc. Digital and Cyber Forensic Science  
Cybersecurity / Digital Forensics Student
