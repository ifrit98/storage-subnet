from unittest import TestCase
from parameterized import parameterized


from storage.miner.set_weights import should_wait_to_set_weights


class TestSetWeights(TestCase):
    @parameterized.expand(
        [
            [0, 0, 360, True],
            [179, 0, 360, True],
            [180, 0, 360, True],
            [181, 0, 360, False],
            [360, 0, 360, False],
            [500, 0, 360, False],
        ]
    )
    def test_should_wait_to_set_weights(
        self, current_block, last_epoch_block, tempo, expected
    ):
        should_keep_waiting = should_wait_to_set_weights(
            current_block, last_epoch_block, tempo
        )

        self.assertEqual(expected, should_keep_waiting)
