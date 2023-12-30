from unittest import TestCase
from parameterized import parameterized


from storage.miner.set_weights import should_wait_to_set_weights


class TestSetWeights(TestCase):
    @parameterized.expand(
        [
            [1000, 700, 360, False],
            [1000, 800, 360, False],
            [1000, 820, 360, True],
            [1000, 821, 360, True],
            [1000, 822, 360, True],
            [1000, 900, 360, True],
            [1000, 999, 360, True],
            [1000, 1000, 360, True],
        ]
    )
    def test_should_wait_to_set_weights(self, current_block, last_epoch_block, set_weights_epoch_length, expected):
        should_keep_waiting = should_wait_to_set_weights(
            current_block, 
            last_epoch_block,
            set_weights_epoch_length)

        self.assertEqual(expected, should_keep_waiting)
