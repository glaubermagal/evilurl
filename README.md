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
[*] Homograph characters used: ['һ', 'ƍ', 'ᴛ', 'ս', 'і', 'ᖯ', 'ɡ']
+--------------------+-------------------+----------------+---------+---------------------------------+
| homograph_domain   | punycode          | dns            | mixed   | combinations                    |
+====================+===================+================+=========+=================================+
| ɡithub.com         | xn--ithub-qmc.com | 107.189.22.234 | YES     | ɡ → LATIN SMALL LETTER SCRIPT G |
+--------------------+-------------------+----------------+---------+---------------------------------+
```

## Overview

EvilURL is a Python tool designed to analyze and identify potential Internationalized Domain Name (IDN) homograph attacks. These attacks exploit the visual similarity of characters from different Unicode scripts to create deceptive domain names for phishing and other malicious purposes. EvilURL helps assess the vulnerability of domains to these attacks.

## Motivation

This project aims to raise awareness about the security risks of IDN homograph attacks. By identifying visually similar characters, EvilURL helps users and security professionals understand these vulnerabilities and improve protection against phishing and other cyber threats.

## Installation

1. Clone the repository: `git clone https://github.com/glaubermagal/evilurl.git`
1. Navigate to the project directory: `cd evilurl`
1. Create a virtual environment: python3 -m venv .venv
1. Activate the virtual environment: `source .venv/bin/activate` (Linux/macOS) or `.venv\Scripts\activate` (Windows)
1. Install dependencies: `pip install -r requirements.txt`
1. Install EvilURL: `pip install .` (for local development) or `pip install evilurl` (once published on PyPI)

## Unit Tests

Run unit tests with:

```bash
python -m unittest tests/tests.py
```

## Usage

```
evilurl [OPTIONS] DOMAIN|FILE

Options:
  -f, --file FILE       Path to a file containing a list of domains.
  --domains-only        Output only the generated homograph domains.
  --log-full           Output all generated domains, including unregistered ones.
  --json               Output results in JSON format.
  --mixed-only         Output only mixed-script domains (those using characters from multiple scripts).
  --help                Show this message and exit.
```

**Examples:**
```
evilurl github.com                # Analyze github.com
evilurl example.com --domains-only # Show only homograph domains for example.com
evilurl example.org --log-full      # Show all generated domains for example.org, including unregistered
evilurl -f domains.txt             # Analyze domains from a file
evilurl example.net --json          # Output results in JSON format
evilurl microsoft.com --mixed-only   # Show only mixed-script domains for microsoft.com
evilurl apple.com                 # Analyze apple.com, showing DNS resolution results and character mapping
```

## Unicode Combinations

The tool considers various Unicode combinations for visually similar characters, including Cyrillic, Greek, and Armenian characters. The combinations are defined in the tool to assist in the identification of potential homograph attacks.

In the output, "MIXED NO" indicates that the domain uses a single character family and is typically eligible for registration with most registrars.

## Disclaimer

This tool is intended for ethical hacking purposes only.

## How It Works

1. Extracting the domain parts.
2. Generating variations using visually similar Unicode characters (defined in `unicode_combinations.json`).
3. Constructing potential homograph domains and checking DNS records.
4. Presenting results with punycode, DNS status, mixed-script indicators, and character mappings.


## Identifying and Blocking Malicious Domains

EvilURL helps you proactively identify potentially malicious domains that leverage IDN homograph attacks.  You can generate a list of possible homograph variations for a given domain using the `--domains-only` option:

```bash
evilurl example.com --domains-only
```

Carefully examine the output. Research each generated domain (e.g., using WHOIS lookups, DNS analysis) to determine if it's being used for malicious purposes (phishing, malware distribution, etc.).

If you discover malicious homograph domains, you can compile them into a blocklist file. For example, to create a blocklist for `example.com`, redirect the output of evilurl to a file:

```
evilurl example.com --domains-only > blocklist/example.com
```

This will create (or overwrite) a file named `example.com` within the `blocklist` directory, containing the list of generated homograph domains. You can then use this blocklist with other security tools or systems to prevent access to these potentially harmful domains. (Note: You may need to create the `blocklist` directory if it doesn't already exist).

While EvilURL doesn't have built-in blocklist functionality, generating these lists can be a valuable first step in mitigating homograph attack risks. You can share identified malicious domains with other security researchers or contribute to community-maintained blocklists such as:

- https://github.com/mypdns/matrix
- https://github.com/mitchellkrogza/phishing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.