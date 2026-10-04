import unittest

from pocketledger.ledger import add_entry, balance, normalize_description


class LedgerUnitTests(unittest.TestCase):
    def test_description_is_trimmed_and_internal_whitespace_is_normalized(self):
        self.assertEqual(normalize_description("  bus   ticket "), "bus ticket")

    def test_empty_description_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "cannot be empty"):
            normalize_description("   ")

    def test_zero_amount_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "non-zero"):
            add_entry([], "Coffee", 0)

    def test_balance_sums_income_and_expenses(self):
        entries = [
            {"description": "Allowance", "amount_cents": 5000},
            {"description": "Lunch", "amount_cents": -850},
        ]
        self.assertEqual(balance(entries), 4150)

