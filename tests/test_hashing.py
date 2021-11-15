from unittest import TestCase
from unittest.mock import patch
import hashing


class TestHashing(TestCase):

    @patch('builtins.input', lambda *args: 'sha256')
    def test_algorithm_selection_valid(self):
        self.assertEqual(hashing.choose_hash(), "sha256")
    @patch('builtins.input', lambda *args: 'invalid_hash')
    def test_algorithm_selection_invalid(self):        
        self.assertEqual(hashing.choose_hash(), None)

    @patch('builtins.input', lambda *args: 'sha256')
    def test_hashing(self):        
        self.assertEqual(hashing.hashing(), "5d5b09f6dcb2d53a5fffc60c4ac0d55fabdf556069d6631545f42aa6e3500f2e")

    @patch('builtins.input', lambda *args: 'invalid')
    def test_hashing_invalid(self):        
        self.assertEqual(hashing.hashing(), None)    