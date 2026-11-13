

def handle(data, context):
    state = context['balances']
    if data.get('action') == 'read':
        return {'balances':list(state)}
    pending = [state[0]-10,state[1]+10]
    if data.get('fail_after_debit'):
        return {'error':'Credit failed'},503
    state[:] = pending
    return {'balances':list(state)}
