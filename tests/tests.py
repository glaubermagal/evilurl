import unittest
from pathlib import Path
from unittest.mock import patch

from src.evilurl import (HomographAnalyzer,
                         load_unicode_combinations_from_file, main)


class TestHomographAnalyzer(unittest.TestCase):

    def setUp(self):
        unicode_combinations_file = Path(__file__).resolve().parent.parent / "./src/unicode_combinations.json"
        unicode_combinations = load_unicode_combinations_from_file(unicode_combinations_file)
        self.analyzer = HomographAnalyzer(unicode_combinations, show_domains_only=False, check_dns=False)

    @patch('socket.gethostbyname')
    def test_check_domain_registration(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "127.0.0.1"
        result = self.analyzer.check_domain_registration("example.com")
        self.assertEqual(result, "127.0.0.1")

    def test_extract_domain_parts(self):
        url = "example.com"
        result = self.analyzer.extract_domain_parts(url)
        self.assertEqual(result, ['example', 'com'])

    def test_generate_combinations(self):
        result = self.analyzer.generate_combinations('x')
        print("result", result)
        self.assertEqual(result, ([['x', 'х']], ['х'], ['CYRILLIC']))

    @patch('builtins.print')
    def test_analyze_domain(self, mock_print):
        domain = "m.com"
        self.analyzer.analyze_domain(domain)
        mock_print.assert_called_with("No unicode combinations found for the current character set")

    def test_load_unicode_combinations_from_file(self):
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = '[{"latin":"a","similar":[{"CYRILLIC":{"а":"CYRILLIC SMALL LETTER A"}},{"LATIN":{"ɑ":"LATIN SMALL LETTER ALPHA"}},{"GREEK":{"α":"GREEK SMALL LETTER ALPHA"}},{"APL":{"⍺":"APL FUNCTIONAL SYMBOL ALPHA"}}]}]'
            result = load_unicode_combinations_from_file("fake_file.json")
        self.assertEqual(result, [{"latin":"a","similar":[{"CYRILLIC":{"а":"CYRILLIC SMALL LETTER A"}},{"LATIN":{"ɑ":"LATIN SMALL LETTER ALPHA"}},{"GREEK":{"α":"GREEK SMALL LETTER ALPHA"}},{"APL":{"⍺":"APL FUNCTIONAL SYMBOL ALPHA"}}]}])

    def test_main(self):
        with patch('sys.argv', ['src.evilurl.py', 'example.com']):
            with patch('src.evilurl.HomographAnalyzer.analyze_domain') as mock_analyze_domain:
                main()
                mock_analyze_domain.assert_called_with('example.com')

if __name__ == '__main__':
    unittest.main()
