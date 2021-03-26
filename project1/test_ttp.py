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

def test_retrieve_share():
	my_ttp = TrustedParamGenerator()

    my_ttp.add_participant("Alice")
    my_ttp.add_participant("Bob")
    my_ttp.add_participant("Charlie")

    triplet = my_ttp._generate_triplet(1,1)
    for e in triplet:
        assert(e >= 0 and e <= q)

    assert(1==0)

    print("Test retrieve_share ok")

"""def test():
    print('Running tests...')

    test_participants()

    print('Tests OK')

test()"""