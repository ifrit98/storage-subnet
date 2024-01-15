from unittest import TestCase
from parameterized import parameterized

from storage.validator.state import (
    should_checkpoint,
)


class TestValidatorState(TestCase):
    @parameterized.expand(
        [
            [0, 50, 100, False],
            [50, 50, 100, False],
            [60, 50, 100, False],
            [70, 50, 100, False],
            [80, 50, 100, False],
            [90, 50, 100, False],
            [100, 50, 100, False],
            [149, 50, 100, False],
            [150, 50, 100, True],
            [150, 50, 100, True],
            [151, 50, 100, True],
            [155, 50, 100, True],
            [175, 50, 100, True],
            [200, 50, 100, True],
            [260, 50, 100, True],
            [1080, 50, 100, True],
            [449, 150, 300, False],
            [450, 150, 300, True],
        ]
    )
    def test_should_checkpoint(
        self, current_block, prev_step_block, checkpoint_block_length, expected
    ):
        result = should_checkpoint(
            current_block, prev_step_block, checkpoint_block_length
        )
        self.assertEqual(expected, result)
