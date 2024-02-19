from pathlib import Path
import socket
import sys
from itertools import product
from urllib.parse import urlsplit
import json

header = """
 ██████████ █████   █████ █████ █████          █████  █████ ███████████   █████
░░███░░░░░█░░███   ░░███ ░░███ ░░███          ░░███  ░░███ ░░███░░░░░███ ░░███
 ░███  █ ░  ░███    ░███  ░███  ░███           ░███   ░███  ░███    ░███  ░███
 ░██████    ░███    ░███  ░███  ░███           ░███   ░███  ░██████████   ░███
 ░███░░█    ░░███   ███   ░███  ░███           ░███   ░███  ░███░░░░░███  ░███
 ░███ ░   █  ░░░█████░    ░███  ░███      █    ░███   ░███  ░███    ░███  ░███      █
 ██████████    ░░███      █████ ███████████    ░░████████   █████   █████ ███████████
░░░░░░░░░░      ░░░      ░░░░░ ░░░░░░░░░░░      ░░░░░░░░   ░░░░░   ░░░░░ ░░░░░░░░░░░

[ by @glaubermagal – https://github.com/glaubermagal/evilurl]
"""

class HomographAnalyzer:
    def __init__(self, unicode_combinations, show_domains_only, check_dns):
        self.unicode_combinations = unicode_combinations
        self.show_domains_only = show_domains_only
        self.check_dns = check_dns

    def check_domain_registration(self, domain_name):
        try:
            dns = socket.gethostbyname(domain_name)
            return dns if dns else None
        except socket.error as e:
            return None

    def extract_domain_parts(self, url):
        parsed_url = urlsplit('https://' + url)
        domain_parts = parsed_url.netloc.split('.')
        return domain_parts

    def generate_combinations(self, domain_parts):
        result = []
        chars = set()
        families = set()

        for part in domain_parts:
            variations = [part]
            for char in part:
                similar_chars_entry = next(
                    (entry['similar'][0] for entry in self.unicode_combinations if entry['latin'] == char), None)

                print('similar_chars_entry', similar_chars_entry)
                if similar_chars_entry is not None:
                    family, characters = list(similar_chars_entry.items())[0]
                    chars.update(characters)
                    variations.extend(characters)
                    families.add(family)

            result.append(variations)

        return result, list(chars), list(families)

    def analyze_domain(self, domain):
        domain = domain.lower()
        domain_parts = self.extract_domain_parts(domain)
        result = self.generate_combinations(domain_parts[0])
        combinations = result[0]
        chars = result[1]
        families = result[2]

        unique_domains = set()

        for combination in product(*combinations):
            new_domain = ''.join(combination) + '.' + '.'.join(domain_parts[1:])
            unique_domains.add(new_domain)

        if len(unique_domains) <= 1:
            return print(f"No unicode combinations found for the current character set")

        if not self.show_domains_only:
            print(header)
            print(f"\033[32m[\033[0m*\033[32m]\033[0m Domain: \033[33m{domain}\033[0m")
            print(f"\033[32m[\033[0m*\033[32m]\033[0m Homograph characters used: \033[32m{chars}\033[0m")

        if self.show_domains_only:
            for new_domain in unique_domains:
                punycode_encoded_domain = new_domain.encode('idna').decode()

                if new_domain == punycode_encoded_domain:
                    continue

                print(new_domain)
        else:
            for index, new_domain in enumerate(unique_domains):
                punycode_encoded_domain = new_domain.encode('idna').decode()
                
                if domain == punycode_encoded_domain:
                    continue

                print(f"\n{index + 1} -------------------------------")
                print(f"Homograph Domain: {new_domain}")
                print(f"Punycode: {punycode_encoded_domain}")

                if self.check_dns:
                    dns = self.check_domain_registration(new_domain)
                    if dns:
                        print(f"\033[31mDNS: {dns}\033[0m")
                    else:
                        print(f"DNS: UNSET")
                
                print('\033[33mMixed: NO\033[0m' if punycode_encoded_domain.count("-") == 2 and len(families) == 1 else 'Mixed: YES')

def load_unicode_combinations_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return None

def main():
    unicode_combinations_file = Path(__file__).resolve().parent / "./unicode_combinations.json"
    unicode_combinations = load_unicode_combinations_from_file(unicode_combinations_file)

    if unicode_combinations is not None:
        show_domains_only = False
        check_dns = False

        if '--domains-only' in sys.argv:
            show_domains_only = True
            sys.argv.remove('--domains-only')
        
        if '--dns' in sys.argv:
            check_dns = True
            sys.argv.remove('--dns')

        homograph_analyzer = HomographAnalyzer(unicode_combinations, show_domains_only, check_dns)

        if len(sys.argv) == 2:
            homograph_analyzer.analyze_domain(sys.argv[1])
        elif len(sys.argv) == 3 and sys.argv[1] == '-f':
            try:
                with open(sys.argv[2], 'r') as file:
                    domains = file.read().splitlines()
                    for domain in domains:
                        homograph_analyzer.analyze_domain(domain)
            except FileNotFoundError:
                print(f"Error: File {sys.argv[2]} not found.")
        else:
            print("Usage: python evilurl.py <domain> OR python evilurl.py -f <file_path>")

if __name__ == "__main__":
    main()