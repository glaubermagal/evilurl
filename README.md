# Homograph URL Checker

██████████ █████   █████ █████ █████          █████  █████ ███████████   █████      
░░███░░░░░█░░███   ░░███ ░░███ ░░███          ░░███  ░░███ ░░███░░░░░███ ░░███       
 ░███  █ ░  ░███    ░███  ░███  ░███           ░███   ░███  ░███    ░███  ░███       
 ░██████    ░███    ░███  ░███  ░███           ░███   ░███  ░██████████   ░███       
 ░███░░█    ░░███   ███   ░███  ░███           ░███   ░███  ░███░░░░░███  ░███       
 ░███ ░   █  ░░░█████░    ░███  ░███      █    ░███   ░███  ░███    ░███  ░███      █
 ██████████    ░░███      █████ ███████████    ░░████████   █████   █████ ███████████
░░░░░░░░░░      ░░░      ░░░░░ ░░░░░░░░░░░      ░░░░░░░░   ░░░░░   ░░░░░ ░░░░░░░░░░░ 

![Homograph URL Checker](screenshot.png)

**Author:** Glauber Magal [@glaubermagal]

## Overview

The Homograph URL Checker is a Python tool designed to analyze and identify potential Internationalized Domain Name (IDN) homograph attacks. Homograph attacks involve the use of characters that visually resemble each other but have different Unicode representations. This tool checks for variations of Latin characters that may be exploited for phishing or malicious purposes.

## Motivation

The primary motivation behind this project is to raise awareness about the potential security risks associated with IDN homograph attacks. By identifying visually similar characters, the tool aims to help users and security professionals study and understand the vulnerabilities in domain names, promoting better protection against phishing attempts and other cyber threats.

## Usage

### Single Domain Analysis
To check a single domain, run the tool with the following command:

```bash
python evilurl.py <domain>
```

### Batch Analysis from File
To analyze multiple domains from a file, use the following command:

```bash
python evilurl.py -f <file_path>
```

## Dependencies
- Python 3
- idna library

Create a virtualenv

```bash
python -m venv venv
source venv/bin/activate
```

Install the required library using:

```bash
pip install -r requirements.txt
```

## Unicode Combinations

The tool considers various Unicode combinations for visually similar characters, including Cyrillic, Greek, and Armenian characters. The combinations are defined in the tool to assist in the identification of potential homograph attacks.

## Disclaimer

This tool is intended for educational and research purposes only. The author is not responsible for any misuse of this tool.

## How It Works

1. The tool extracts the domain parts from the provided URL.
2. It generates combinations of visually similar characters for each Latin character in the domain.
3. For each combination, it constructs a new domain and checks its registration status and DNS information.
4. The tool then displays the homograph domains, their punycode representation, and DNS status.

## Example Usage

### Single Domain Analysis
```bash
python evilurl.py example.com
```

### Batch Analysis from File
```bash
python evilurl.py -f domains.txt
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.