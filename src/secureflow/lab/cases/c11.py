def handle(data, context):
    # The lab supplies an authenticated alice session independently of input.
    records = {'alice': 'ALICE_RECORD', 'bob': 'BOB_PRIVATE_RECORD'}
    return {'record': records[data.get('owner', 'alice')]}
