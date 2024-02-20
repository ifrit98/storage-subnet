from unittest import TestCase

from storage.cli.neuroncommand import RunMiner, RunValidator, RunApi


class TestCli(TestCase):
    def test_init_runminer(self):
        n = RunMiner()
        self.assertTrue(type(n) is RunMiner)


    def test_init_runvalidator(self):
        n = RunValidator()
        self.assertTrue(type(n) is RunValidator)

    def test_init_runapi(self):
        n = RunApi()
        self.assertTrue(type(n) is RunApi)
