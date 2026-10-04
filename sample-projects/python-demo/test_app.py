import unittest

from app import normalize_username


class UsernameTests(unittest.TestCase):
    def test_trims_whitespace(self):
        self.assertEqual(normalize_username("  Sam  "), "Sam")


if __name__ == "__main__":
    unittest.main()
