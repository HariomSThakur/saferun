import unittest

from app import normalize_username


class UsernameTests(unittest.TestCase):
    def test_normalizes_case_and_whitespace(self):
        self.assertEqual(normalize_username("  Sam  "), "sam")  # Deliberately failing demo assertion.


if __name__ == "__main__":
    unittest.main()
