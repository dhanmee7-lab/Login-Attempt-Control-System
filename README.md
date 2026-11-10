\# Login Attempt Control System



\## Overview

A Python-based cybersecurity project that monitors login attempts and protects accounts against repeated failed authentication and brute-force attacks.



\## Features

\- Login authentication

\- Failed login attempt tracking

\- Username-based monitoring

\- IP address-based monitoring

\- Account lockout after 5 consecutive failed attempts

\- Temporary lockout for 15 minutes

\- Security audit logging using JSON

\- Brute-force attack simulation

\- Password hashing using PBKDF2-HMAC-SHA256



\## Technologies Used

\- Python 3

\- hashlib

\- hmac

\- JSON

\- datetime

\- pathlib



\## Demo Credentials

\- Username: alice

\- Password: AliceSecure123!



\- Username: admin

\- Password: AdminSecure123!



\*\*Note:\*\* Demo credentials are for local testing only.



\## How to Run



1\. Clone the repository.

2\. Navigate to the project directory.

3\. Create and activate a virtual environment.

4\. Run:



```bash

python login\_attempt\_control.py

```



\## Security Configuration

\- Maximum failed attempts: 5

\- Lockout duration: 15 minutes

\- Password hashing: PBKDF2-HMAC-SHA256

\- Audit log: logs/security\_audit.log



\## Project Structure



```text

Login-Attempt-Control-System/

├── login\_attempt\_control.py

├── README.md

├── requirements.txt

├── .gitignore

├── logs/

└── screenshots/

```



\## Limitations

This is a local educational prototype. Account counters and lockout information are stored in memory and reset when the application restarts. IP addresses are manually supplied for simulation rather than obtained from real network connections.



\## Disclaimer

This project is intended for educational cybersecurity testing in a controlled local environment.

