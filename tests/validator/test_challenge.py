from unittest import TestCase

from storage.validator.challenge import _filter_verified_responses


class TestChallenge(TestCase):
    def test_challenge_data_when_none(self):
        input_uids = [19, 14, 9]
        responses = [
            (None, [1, 2, 3]),
            (None, [4, 5, 6]),
            (None, [7, 8, 9]),
        ]

        uids, responses = _filter_verified_responses(input_uids, responses)

        self.assertEqual((), uids)
        self.assertEqual((), responses)

    def test_challenge_data_when_no_none(self):
        uids = [19, 14, 9]
        responses = [
            ("some_1", [1, 2, 3]),
            ("some_2", [4, 5, 6]),
            ("some_3", [7, 8, 9]),
        ]

        uids, responses = _filter_verified_responses(uids, responses)

        self.assertEqual((19, 14, 9), uids)
        self.assertEqual((1, 4, 7), responses)
