# EvilURL Checker

```bash
evilurl git:(main) ✗ evilurl github.com

 ██████████ █████   █████ █████ █████          █████  █████ ███████████   █████
░░███░░░░░█░░███   ░░███ ░░███ ░░███          ░░███  ░░███ ░░███░░░░░███ ░░███
 ░███  █ ░  ░███    ░███  ░███  ░███           ░███   ░███  ░███    ░███  ░███
 ░██████    ░███    ░███  ░███  ░███           ░███   ░███  ░██████████   ░███
 ░███░░█    ░░███   ███   ░███  ░███           ░███   ░███  ░███░░░░░███  ░███
 ░███ ░   █  ░░░█████░    ░███  ░███      █    ░███   ░███  ░███    ░███  ░███      █
 ██████████    ░░███      █████ ███████████    ░░████████   █████   █████ ███████████
░░░░░░░░░░      ░░░      ░░░░░ ░░░░░░░░░░░      ░░░░░░░░   ░░░░░   ░░░░░ ░░░░░░░░░░░

[ by @glaubermagal – https://github.com/glaubermagal/evilurl]

[*] Domain: github.com
[*] Homograph characters used: ['Ꮟ', 'ɡ', 'һ', 'Ꮒ', 'ᖯ', 'ᴜ', 'т', 'і', 'ց', 'ƍ', 'τ', 'ս', 'Ь', 'ᴛ', 'ⅰ']

1 -------------------------------
homograph domain: ցiᴛһuᏏ.com
punycode: xn--iu-4wc40fg77fqy2p.com
DNS: UNSET
MIXED: YES

2 -------------------------------
homograph domain: gⅰτᏂub.com
punycode: xn--giub-rod2688w.com
DNS: UNSET
MIXED: YES

3 -------------------------------
homograph domain: ƍiтһuЬ.com
punycode: xn--iu-cxa78yqb86b.com
DNS: UNSET
MIXED: YES
```

## Overview

The Homograph URL Checker is a Python tool designed to analyze and identify potential Internationalized Domain Name (IDN) homograph attacks. Homograph attacks involve the use of characters that visually resemble each other but have different Unicode representations. This tool checks for variations of Latin characters that may be exploited for phishing or malicious purposes.

## Motivation

The primary motivation behind this project is to raise awareness about the potential security risks associated with IDN homograph attacks. By identifying visually similar characters, the tool aims to help users and security professionals study and understand the vulnerabilities in domain names, promoting better protection against phishing attempts and other cyber threats.

## Installation

```bash
pip install evilurl
```

## Dependencies for Local Installation
- Python 3

Create a virtualenv

```bash
python -m venv venv
source venv/bin/activate
```

Install the required library using:

```bash
pip install -r requirements.txt
```

## Unit Tests

To run the unit tests, use the following command:

```bash
python -m unittest tests/tests.py
```

## Usage

### Single Domain Analysis
To check a single domain, run the tool with the following command:

```bash
evilurl <domain>
```

### Batch Analysis from File
To analyze multiple domains from a file, use the following command:

```bash
evilurl -f <file_path>
```

## Unicode Combinations

The tool considers various Unicode combinations for visually similar characters, including Cyrillic, Greek, and Armenian characters. The combinations are defined in the tool to assist in the identification of potential homograph attacks.

In the output, "MIXED NO" indicates that the domain uses a single character family and is typically eligible for registration with most registrars.

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
evilurl example.com
```

### Batch Analysis from File
```bash
evilurl -f domains.txt
```

### Return only the homograph domains
```bash
evilurl example.com --domains-only
```

### Output the DNS registration status
```bash
evilurl example.com --dns
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.