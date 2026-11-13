

def handle(data, context):
    state = context['balances']
    if data.get('action') == 'read':
        return {'balances':list(state)}
    state[0] -= 10
    if data.get('fail_after_debit'):
        return {'error':'Credit failed'},503
    state[1] += 10
    return {'balances':list(state)}
