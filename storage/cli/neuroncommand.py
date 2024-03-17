# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# Copyright © 2023 philanthrope

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

from argparse import ArgumentParser
from bittensor import config as bt_config

from neurons.miner import run_miner
from neurons.validator import run_validator
from neurons.api import run_api


class RunApi:

    @staticmethod
    def run(cli):
        r"""Run api neuron"""
        run_api()
    
    @staticmethod
    def check_config(config: "bt_config"):
        pass

    @staticmethod
    def add_args(parser: ArgumentParser):
        parser.add_parser("api", help="""Run api neuron""")


class RunMiner:

    @staticmethod
    def run(cli):
        r"""Run miner neuron"""
        run_miner()
    
    @staticmethod
    def check_config(config: "bt_config"):
        pass

    @staticmethod
    def add_args(parser: ArgumentParser):
        parser.add_parser("miner", help="""Run miner neuron""")


class RunValidator:

    @staticmethod
    def run(cli):
        r"""Run validator neuron"""
        run_validator()
    
    @staticmethod
    def check_config(config: "bt_config"):
        pass

    @staticmethod
    def add_args(parser: ArgumentParser):
        parser.add_parser("validator", help="""Run validator neuron""")