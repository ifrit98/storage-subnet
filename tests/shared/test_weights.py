from unittest import TestCase
from parameterized import parameterized


from storage.shared.weights import should_wait_to_set_weights, should_set_weights


class TestWeights(TestCase):
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

    @parameterized.expand(
        [
            [0, 0, 360, False],
            [1, 0, 360, False],
            [100, 0, 360, False],
            [110, 0, 360, False],
            [200, 0, 360, True],
            [0, 10, 360, False],
            [8, 10, 360, False],
            [10, 10, 360, False],
            [11, 10, 360, False],
            [188, 10, 360, False],
            [189, 10, 360, False],
            [190, 10, 360, False],
            [191, 10, 360, True],
            [200, 10, 360, True],
            [300, 10, 360, True],
            [1000, 10, 360, True],
        ]
    )
    def test_should_set_weights(self, current_block, last_epoch_block, tempo, expected):
        result = should_set_weights(current_block, last_epoch_block, tempo, False)
        self.assertEqual(expected, result)
