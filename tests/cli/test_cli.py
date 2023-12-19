from unittest import TestCase

from storage.cli import cli


class TestCli(TestCase):
    def test_cli_empty_call_as_list_then_systemexit(self):
        args = []
        with self.assertRaises(SystemExit):
            self.sut = cli(args=args)

    def test_cli_empty_call_as_none_then_systemexit(self):
        args = None
        with self.assertRaises(SystemExit):
            self.sut = cli(args=args)
