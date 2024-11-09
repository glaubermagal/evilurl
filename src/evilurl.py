import pandas as pd
import argparse
from pathlib import Path
import socket
import sys
from itertools import product
from urllib.parse import urlsplit
import json
from tabulate import tabulate
import tldextract


TABLE_HEADERS=["homograph_domain", "punycode", "dns", "mixed", "combinations"]
HEADER = """
\033[31m ██████████ █████   █████ █████ █████          █████  █████ ███████████   █████
░░███░░░░░█░░███   ░░███ ░░███ ░░███          ░░███  ░░███ ░░███░░░░░███ ░░███
 ░███  █ ░  ░███    ░███  ░███  ░███           ░███   ░███  ░███    ░███  ░███
 ░██████    ░███    ░███  ░███  ░███           ░███   ░███  ░██████████   ░███
 ░███░░█    ░░███   ███   ░███  ░███           ░███   ░███  ░███░░░░░███  ░███
 ░███ ░   █  ░░░█████░    ░███  ░███      █    ░███   ░███  ░███    ░███  ░███      █
 ██████████    ░░███      █████ ███████████    ░░████████   █████   █████ ███████████
░░░░░░░░░░      ░░░      ░░░░░ ░░░░░░░░░░░      ░░░░░░░░   ░░░░░   ░░░░░ ░░░░░░░░░░░

[ by @glaubermagal – https://github.com/glaubermagal/evilurl]\033[0m
"""

class HomographAnalyzer:
    def __init__(self, unicode_combinations, show_domains_only, show_mixed_only, show_registered_only, json_format):
        self.unicode_combinations = unicode_combinations
        self.show_domains_only = show_domains_only
        self.show_mixed_only = show_mixed_only
        self.json_format = json_format
        self.show_registered_only = show_registered_only
        self.character_descriptions = {}
        
        for item in self.unicode_combinations:
            for similar_dict in item['similar']:
                for script, char_map in similar_dict.items():
                    self.character_descriptions.update(char_map)

    @staticmethod
    def colored_text(text, color_code):
        return f"\033[{color_code}m{text}\033[0m"

    def is_mixed_domain(self, punycode_encoded_domain, families):
        return not (punycode_encoded_domain.count("-") == 2 and len(families) == 1)
    
    def check_domain_registration(self, domain_name):
        try:
            return socket.gethostbyname(domain_name)
        except socket.error:
            return None

    def generate_combinations(self, domain_parts):
        result = []
        chars, families = set(), set()

        for part in domain_parts:
            variations = [part]
            for char in part:
                similar_chars_entry = next(
                    (entry['similar'][0] for entry in self.unicode_combinations if entry['latin'] == char), None)
                if similar_chars_entry:
                    family, characters = list(similar_chars_entry.items())[0]
                    chars.update(characters)
                    variations.extend(characters)
                    families.add(family)
            result.append(variations)

        return result, list(chars), list(families)

    def analyze_domain(self, domain):
        domain = domain.lower()
        domain_parts = tldextract.extract(domain)
        combinations, chars, families = self.generate_combinations(domain_parts.domain)

        unique_domains = {''.join(comb) for comb in product(*combinations)}
        if len(unique_domains) <= 1:
            return print(self.colored_text("No unicode combinations found for the current character set", 31))

        if not self.show_domains_only:
            print(HEADER)
            print(f"{self.colored_text('[*]', 32)} Domain: {self.colored_text(domain, 33)}")
            print(f"{self.colored_text('[*]', 32)} Homograph characters used: {self.colored_text(chars, 32)}")

        table_data = []
        for index, main_domain_part in enumerate(unique_domains):
            full_domain = main_domain_part + '.' + domain_parts.suffix
            formatted_combinations = []
            punycode_encoded_domain = main_domain_part.encode('idna').decode()
            punycode_encoded_full_domain = punycode_encoded_domain + '.' + domain_parts.suffix
            if full_domain == punycode_encoded_full_domain:
                continue

            dns = self.check_domain_registration(full_domain)
            if (not dns and self.show_registered_only) or (self.show_mixed_only and not self.is_mixed_domain(punycode_encoded_domain, families)):
                continue

            for part in main_domain_part:
                for char in part:
                    if char in self.character_descriptions.keys():
                        formatted_combinations.append(f"{char} → {self.character_descriptions.get(char)}")

            if self.show_domains_only:
                print(full_domain)
                continue

            combinations_str = "\n".join(formatted_combinations)
            table_data.append([
                full_domain,
                punycode_encoded_full_domain,
                dns if dns else 'UNSET',
                "YES" if self.is_mixed_domain(punycode_encoded_domain, families) else self.colored_text("NO", 33),
                combinations_str
            ])

        if self.json_format:
            df = pd.DataFrame(table_data, columns=TABLE_HEADERS)
            json_output = df.to_dict(orient="records")
            print(json.dumps(json_output, indent=4))
            return

        if not self.show_domains_only:
            print(tabulate(table_data, TABLE_HEADERS, tablefmt="grid"))


def load_unicode_combinations_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return None

def main():
    parser = argparse.ArgumentParser(description="Homograph Domain Analyzer")
    parser.add_argument("domain", nargs="?", help="Domain to analyze")
    parser.add_argument("-f", "--file", help="File path with domains to analyze")
    parser.add_argument("--domains-only", action="store_true", help="Show domains only")
    parser.add_argument("--mixed-only", action="store_true", help="Show mixed domains only")
    parser.add_argument("--json", action="store_true", help="Shows the output as a JSON object")
    parser.add_argument("--log-full", action="store_true", help="Log all information, including unregistered domains")

    args = parser.parse_args()

    unicode_combinations_file = Path(__file__).resolve().parent / "./unicode_combinations.json"
    unicode_combinations = load_unicode_combinations_from_file(unicode_combinations_file)

    if unicode_combinations:
        show_domains_only = args.domains_only
        show_mixed_only = args.mixed_only
        json_format = not not args.json
        show_registered_only = not args.log_full

        homograph_analyzer = HomographAnalyzer(
            unicode_combinations, show_domains_only, show_mixed_only, show_registered_only, json_format
        )

        if args.domain:
            homograph_analyzer.analyze_domain(args.domain)
        elif args.file:
            try:
                with open(args.file, 'r') as file:
                    for domain in file.read().splitlines():
                        homograph_analyzer.analyze_domain(domain)
            except FileNotFoundError:
                print(f"Error: File {args.file} not found.")
        else:
            parser.print_help()

if __name__ == "__main__":
    main()
