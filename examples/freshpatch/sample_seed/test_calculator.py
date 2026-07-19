import unittest

from calculator import average


class AverageTests(unittest.TestCase):
    def test_preserves_fractional_result(self):
        self.assertEqual(average(5, 2), 2.5)


if __name__ == "__main__":
    unittest.main()
