from unittest import TestCase
from parameterized import parameterized
from storage.validator.state import should_checkpoint


class TestShouldCheckpoint(TestCase):
    @parameterized.expand(
        [
            [1001, 500, 100, True],  # been 501 blocks
            [1001, 902, 100, False],  # been 99 blocks
            [1001, 900, 100, True],  # been 101 blocks
            [1001, 899, 100, True],  # been 102 blocks
            [1001, 901, 100, True],  # been 100 blocks
            [1001, 950, 100, False],  # been 51 blocks
            [1001, 999, 100, False],  # been 2 blocks
            [1001, 1000, 100, False],  # been 1 blocks
        ]
    )
    def test_condition_should_checkpoint(
        self, current_block, prev_step_block, checkpoint_block_length, expected
    ):
        result = should_checkpoint(
            current_block, prev_step_block, checkpoint_block_length
        )
        self.assertEqual(expected, result)
