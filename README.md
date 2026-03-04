# Domain Security Scanner

## Overview

Domain Security Scanner is a Flask-based web application designed to analyze the security configuration of a given domain.
The application performs multiple DNS and network security checks, including email authentication mechanisms and HTTPS configuration. It generates a detailed security report that helps identify potential security weaknesses in domain configurations.

---

## Features

The application provides the following security analysis capabilities:

* MX Record Analysis
* SPF Record Verification
* DMARC Policy Detection
* DKIM Configuration Detection
* DNSSEC Availability Check
* HTTPS Security Verification
* Open Port Scanning
* Email Security Score Calculation
* PDF Security Report Generation

---

## System Architecture

The system follows a simple web-based architecture where the user interacts with a Flask application that performs DNS and network analysis and returns a structured report.

```
+-------------+
|    User     |
+-------------+
        |
        v
+----------------------+
|  Web Browser (UI)    |
|  HTML / CSS          |
+----------------------+
        |
        v
+----------------------+
|  Flask Web Server    |
|  (app.py)            |
+----------------------+
        |
        v
+------------------------------+
|  Security Analysis Module    |
|  (dns_utils.py)              |
|                              |
|  - MX Record Check           |
|  - SPF Analysis              |
|  - DMARC Analysis            |
|  - DKIM Detection            |
|  - DNSSEC Check              |
|  - HTTPS Verification        |
|  - Port Scanning             |
+------------------------------+
        |
        v
+-----------------------+
|  Security Report      |
|  Web Output / PDF     |
+-----------------------+
```

---

## Technology Stack

The project is built using the following technologies:

* Python
* Flask Web Framework
* DNSPython for DNS analysis
* HTML and CSS for frontend interface
* xhtml2pdf for report generation

---

## Project Structure

```
domain-security-scanner
│
├── app.py
├── dns_utils.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── templates
│   ├── index.html
│   └── report.html
│
└── static
```

---

## Installation

### Clone the Repository

```
git clone https://github.com/BHARATHKUMARN66/domain-security-scanner.git
cd domain-security-scanner
```

### Install Dependencies

```
pip install -r requirements.txt
```

### Run the Application

```
python app.py
```

### Access the Application

Open a browser and navigate to:

```
http://127.0.0.1:5000
```

---

## Application Workflow

1. The user enters a domain name in the web interface.
2. The Flask application processes the request.
3. DNS and security checks are performed using the analysis module.
4. Results are displayed as a structured security report.
5. The report can optionally be exported as a PDF document.

---

## Screenshots

Screenshots demonstrating the application interface can be placed in a `screenshots` directory.

Example:

```
screenshots/
    homepage.png
    security_report.png
```

---

## License

This project is distributed under the MIT License.

---

## Author

Bharath Kumar N
GitHub: https://github.com/BHARATHKUMARN66
