"""
Unit tests for the trusted parameter generator.
Testing ttp is not obligatory.

MODIFY THIS FILE.
"""

from ttp import TrustedParamGenerator

def test_participants():
	my_ttp = TrustedParamGenerator()

	assert len(my_ttp.participant_ids) == 0
	my_ttp.add_participant("Alice")
	my_ttp.add_participant("Bob")
	assert len(my_ttp.participant_ids) == 2
	my_ttp.add_participant("Charlie")
	my_ttp.add_participant("Denis")
	assert len(my_ttp.participant_ids) == 4
	my_ttp.add_participant("Charlie")
	my_ttp.add_participant("Denis")
	assert len(my_ttp.participant_ids) == 4

	for p in my_ttp.participant_ids:
		assert (p in ["Alice", "Bob", "Charlie", "Denis"])

	print("Test participants ok")

"""def test():
    print('Running tests...')

    test_participants()

    print('Tests OK')

test()"""