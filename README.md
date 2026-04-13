Phishing Email Analyzer
Overview

The Phishing Email Analyzer is a Python-based tool designed to detect phishing attempts in email messages. It processes raw email files (.eml or .txt) and generates a structured report highlighting potential security risks, suspicious patterns, and a quantified phishing risk score.

This tool is intended for educational purposes, cybersecurity analysis, and basic threat detection.

Features
Comprehensive email inspection:
Sender and domain validation
Email header analysis (SPF, DKIM, DMARC indicators)
URL and hyperlink inspection
Content-based phishing detection
Spelling and grammar evaluation
Attachment analysis
Risk scoring system:
Score range: 0–100
Risk levels: CLEAN, LOW, MEDIUM, HIGH, CRITICAL
Detailed reporting:
Categorized findings with severity levels (HIGH, MEDIUM, LOW)
Human-readable terminal output
JSON export support for integration and further analysis
Demo mode with a built-in phishing sample
Requirements

This project uses only Python standard libraries and does not require external dependencies.

Modules used include:

email
re
json
urllib.parse
datetime
html.parser
collections
textwrap
sys
os
Installation

Clone the repository:

git clone https://github.com/your-username/phishing-email-analyzer.git
cd phishing-email-analyzer

No additional installation steps are required.

Usage
Analyze an Email File
python phishing_analyzer.py <email_file>

Example:

python phishing_analyzer.py sample_phishing.eml
Run Demo Mode
python phishing_analyzer.py --demo
Export JSON Report
python phishing_analyzer.py sample.eml --json

The JSON report will be saved in the current directory.

Output Description

The tool generates a structured report that includes:

Email metadata (From, To, Subject, Date, etc.)
Phishing risk score and classification
Number of detected indicators categorized by severity
Detailed findings with explanations and supporting evidence
Recommended actions for handling the email
Detection Methodology
Sender Analysis
Detection of typo-squatted domains
Identification of suspicious top-level domains
Mismatch between display name and actual sender domain
Header Analysis
Missing or failed authentication checks (SPF, DKIM, DMARC)
Suspicious email client indicators
Inconsistencies in the received mail chain
Link Analysis
Mismatch between displayed and actual URLs
Detection of redirection patterns
Identification of IP-based links
Detection of links pointing to executable files
Content Analysis
Detection of urgency and threat-based language
Identification of requests for sensitive information
Analysis of excessive punctuation and capitalization
Attachment Analysis
Detection of executable attachments
Identification of double-extension filenames
Flagging potentially malicious document types
Project Structure
phishing-email-analyzer/
│── phishing_analyzer.py
│── README.md
│── sample_emails/
How It Works
The tool parses the email using Python’s built-in email module.
It extracts headers, body content (text and HTML), links, and attachments.
Multiple heuristic checks are applied across different categories.
Each detected issue contributes to a weighted phishing score.
A final report is generated with a risk classification and actionable insights.
Limitations
The tool relies on heuristic-based detection and may produce false positives or false negatives.
It does not replace enterprise-grade email security solutions.
No real-time threat intelligence integration is included.
Future Enhancements
Integration of machine learning models for improved detection accuracy
Graphical user interface for ease of use
Real-time email monitoring capability
Integration with external threat intelligence APIs
Browser or email client extensions
Author

Chiranth S

License

This project is intended for academic and research purposes.
