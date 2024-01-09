import sys
import socket
from urllib.parse import urlsplit
from itertools import product
import idna

header = f"""
██████████ █████   █████ █████ █████          █████  █████ ███████████   █████      
░░███░░░░░█░░███   ░░███ ░░███ ░░███          ░░███  ░░███ ░░███░░░░░███ ░░███       
 ░███  █ ░  ░███    ░███  ░███  ░███           ░███   ░███  ░███    ░███  ░███       
 ░██████    ░███    ░███  ░███  ░███           ░███   ░███  ░██████████   ░███       
 ░███░░█    ░░███   ███   ░███  ░███           ░███   ░███  ░███░░░░░███  ░███       
 ░███ ░   █  ░░░█████░    ░███  ░███      █    ░███   ░███  ░███    ░███  ░███      █
 ██████████    ░░███      █████ ███████████    ░░████████   █████   █████ ███████████
░░░░░░░░░░      ░░░      ░░░░░ ░░░░░░░░░░░      ░░░░░░░░   ░░░░░   ░░░░░ ░░░░░░░░░░░ 

[ by GLAUBERMAGAL - Glauber Magal @glaubermagal ]
"""

unicode_combinations = [
    {
        'latin': 'a',
        'similar': [
            {
                '\u0430': 'Cyrillic Small Letter A',
                '\u0251': 'Latin Small Letter Alpha'
            }
        ]
    },
    {
        'latin': 'b',
        'similar': [
            {
                '\u1E05': 'Latin Small Letter B with Underdot',
            }
        ]
    },
    {
        'latin': 'c',
        'similar': [
            {
                '\u03F2': 'Greek Lunate Sigma Symbol'
            }
        ]
    },
    {
        'latin': 'e',
        'similar': [
            {
                '\u0435': 'Cyrillic Small Letter Ye'
            }
        ]
    },
    {
        'latin': 'o',
        'similar': [
            {
                '\u043E': 'Cyrillic Small Letter O',
                '\u03BF': 'Greek small letter Omicron',
                '\u006F': 'Latin small letter O',
                '\u0585': 'Armenian Small Letter Oh',
            }
        ]
    },
    {
        'latin': 'p',
        'similar': [
            {
                '\u0440': 'Cyrillic Small Letter Er'
            }
        ]
    },
    {
        'latin': 's',
        'similar': [
            {
                '\u0455': 'Cyrillic Small Letter Dze'
            }
        ]
    },
    {
        'latin': 'd',
        'similar': [
            {
                '\u0501': 'Cyrillic Capital Letter Komi Dzje'
            }
        ]
    },
    {
        'latin': 'l',
        'similar': [
            {
                '\u0269': 'Latin Small Letter I With Stroke'
            }
        ]
    },
    {
        'latin': 'g',
        'similar': [
            {
                '\u0261': 'Latin Small Letter Script G'
            }
        ]
    },
    {
        'latin': 'n',
        'similar': [
            {
                '\u0578': 'Armenian Small Letter Vo'
            }
        ]
    },
    {
        'latin': 'u',
        'similar': [
            {
                '\u057D': 'Armenian Small Letter Se'
            }
        ]
    },
]

def convert_to_punycode(input_string):
    try:
        punycode = idna.encode(input_string)
        return punycode.decode('utf-8')
    except UnicodeError:
        # Handle errors, such as invalid input
        return None

def check_domain_registration(domain_name):
    try:
        dns = socket.gethostbyname(domain_name)
        if dns:
            return dns
        else:
            return None
    except socket.error as e:
        return None

def extract_domain_parts(url):
    parsed_url = urlsplit('https://' + url)
    domain_parts = parsed_url.netloc.split('.')
    return domain_parts

def generate_combinations(domain_parts, unicode_combinations):
    result = []
    chars = []

    for part in domain_parts:
        variations = [part]
        for char in part:
            for entry in unicode_combinations:
                if entry['latin'] == char:
                    similar_chars = [similar_char for similar_char in entry['similar'][0]]
                    chars.append(similar_chars)
                    variations.extend(similar_chars)
                    break
        result.append(variations)

    return (result, chars)

def analyze_domain(domain):
    domain_parts = extract_domain_parts(domain)
    result = generate_combinations(domain_parts[0], unicode_combinations)
    combinations = result[0]
    chars = result[1]

    domains = []
    for combination in product(*combinations):
        new_domain = ''.join(combination) + '.' + domain_parts[1]
        domains.append(new_domain)

    if len(domains) <= 1:
        print(f"IDN homograph attack is not possible for this domain")

    print(header)
    print(f"\033[32m[\033[0m*\033[32m]\033[0m Domain: \033[33m{domain}\033[0m")
    print(f"\033[32m[\033[0m*\033[32m]\033[0m Unicode characters used: \033[32m{chars}\033[0m")

    for index, new_domain in enumerate(domains[1:]):
        print(f"\n{index+1} -------------------------------")

        dns = check_domain_registration(new_domain)
        punnycode_encoded_domain = convert_to_punycode(new_domain)

        print(f"homograph domain: {new_domain}")
        print(f"punnycode: {punnycode_encoded_domain}")
        if dns:
            print(f"DNS: \033[31m {dns}\033[0m")
        else:
            print(f"DNS: \033[32m NOT IN USE\033[0m")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        analyze_domain(sys.argv[1])
    elif len(sys.argv) == 3 and sys.argv[1] == '-f':
        try:
            with open(sys.argv[2], 'r') as file:
                domains = file.read().splitlines()
                for domain in domains:
                    analyze_domain(domain)
        except FileNotFoundError:
            print(f"Error: File {sys.argv[2]} not found.")
    else:
        print("Usage: python evilurl.py <domain> OR python evilurl.py -f <file_path>")