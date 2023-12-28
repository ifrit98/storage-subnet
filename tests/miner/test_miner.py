from unittest import TestCase
from parameterized import parameterized


from storage.miner.run import should_wait_until_next_epoch


class TestMinerRun(TestCase):
    @parameterized.expand([
        [1000, 500, 100, False],
        [1000, 800, 100, False],
        [1000, 899, 100, False],
        [1000, 900, 100, False],
        [1000, 901, 100, True],
        [1000, 999, 100, True],
        [1000, 1000, 100, True],
    ])
    def test_condition_to_wait_until_next_epoch(self, current_block, last_epoch_block, set_weights_epoch_length, expected):
        should_keep_waiting = should_wait_until_next_epoch(
            current_block, 
            last_epoch_block,
            set_weights_epoch_length)

        self.assertEqual(expected, should_keep_waiting)
