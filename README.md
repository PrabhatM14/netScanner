# Network Scanner

This project is a simple network scanner written in Python. It scans a specified network range to identify active hosts and checks for open common ports on those hosts. It also performs reverse DNS lookups to retrieve hostnames.

## Features

- Validates the target network range.
- Pings hosts to check if they are alive.
- Scans common ports (e.g., HTTP, FTP, SSH) for each active host.
- Performs reverse DNS lookups to get hostnames.
- Outputs a detailed scan report.

## Requirements

- Python 3.x
- Required libraries:
  - `socket`
  - `ipaddress`
  - `threading`
  - `queue`
  - `os`
  - `subprocess`

## Usage

1. Clone the repository:
   ```
   git clone <repository-url>
   ```

2. Navigate to the project directory:
   ```
   cd netScanner
   ```

3. Run the network scanner:
   ```
   python netScanner.py
   ```

4. Enter the network range when prompted (e.g., `192.168.1.0/24`).

## Notes

- Ensure you have the necessary permissions to scan the network.
- The script may require administrative privileges depending on the operating system and network configuration.