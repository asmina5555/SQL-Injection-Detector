The SQL Injection Detector is a Python-based tool designed to identify SQL injection vulnerabilities in web applications. 
It leverages the power of Python libraries like BeautifulSoup for HTML parsing and Tkinter for creating a user-friendly graphical interface. 
The tool automates the process of detecting SQL injection vulnerabilities by injecting malicious payloads into URLs and forms, analyzing server responses, and displaying results in real-time.

Features

1. Payload Injection: Injects malicious SQL payloads into URLs  and forms.
2. Vulnerability Detection: Detects SQL injection vulnerabilities by analyzing server responses for common SQL error messages.
3. User-Friendly GUI: Provides an intuitive Tkinter-based interface for inputting URLs, initiating scans, and viewing results.
4. Real-Time Feedback: Displays scan results in real-time, including details of vulnerable forms and URLs.

Requirements

1. Python 3.6 or higher.
2. Libraries: requests, beautifulsoup4, tkinter.
