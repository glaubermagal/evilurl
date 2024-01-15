from pathlib import Path
import socket
import sys
from itertools import product
from urllib.parse import urlsplit
import idna
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
    def __init__(self, unicode_combinations, show_domains_only):
        self.unicode_combinations = unicode_combinations
        self.show_domains_only = show_domains_only

    def convert_to_punycode(self, input_string):
        try:
            punycode = idna.encode(input_string)
            return punycode.decode('utf-8')
        except UnicodeError:
            return None

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

        for part in domain_parts:
            variations = [part]
            for char in part:
                similar_chars = next((entry['similar'][0] for entry in self.unicode_combinations if entry['latin'] == char), [])
                chars.update(similar_chars)
                variations.extend(similar_chars)

            result.append(variations)

        return result, list(chars)

    def analyze_domain(self, domain):
        domain = domain.lower()
        domain_parts = self.extract_domain_parts(domain)
        result = self.generate_combinations(domain_parts[0])
        combinations = result[0]
        chars = result[1]

        domains = []
        for combination in product(*combinations):
            new_domain = ''.join(combination) + '.' + '.'.join(domain_parts[1:])
            domains.append(new_domain)

        if len(domains) <= 1:
            return print(f"IDN homograph attack is not possible for this domain with the current character set")

        if not self.show_domains_only:
            print(header)
            print(f"\033[32m[\033[0m*\033[32m]\033[0m Domain: \033[33m{domain}\033[0m")
            print(f"\033[32m[\033[0m*\033[32m]\033[0m Homograph characters used: \033[32m{chars}\033[0m")

        if self.show_domains_only:
            for new_domain in domains[1:]:
                print(new_domain)
        else:
            for index, new_domain in enumerate(domains[1:]):
                dns = self.check_domain_registration(new_domain)
                punycode_encoded_domain = self.convert_to_punycode(new_domain)
                
                if new_domain == punycode_encoded_domain:
                    continue
                
                print(f"\n{index + 1} -------------------------------")
                print(f"homograph domain: {new_domain}")
                print(f"punycode: {punycode_encoded_domain}")
                if dns:
                    print(f"DNS: \033[31m {dns}\033[0m")
                else:
                    print(f"DNS: \033[33m UNSET\033[0m")

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

        if '-d' in sys.argv:
            show_domains_only = True
            sys.argv.remove('-d')

        homograph_analyzer = HomographAnalyzer(unicode_combinations, show_domains_only)

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