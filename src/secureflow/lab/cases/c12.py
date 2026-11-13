def handle(data, context):
    records = {'alice': 'ALICE_RECORD', 'bob': 'BOB_PRIVATE_RECORD'}
    owner = data.get('owner', 'alice')
    if owner != context['actor']:
        return {'error': 'Forbidden'}, 403
    return {'record': records[owner]}
