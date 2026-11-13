

def handle(data, context):
    if data.get('action') == 'events':
        return {'events':context['events']}
    valid = data.get('password') == 'lab-valid-passphrase'
    if valid:
        context['events'].append('LOGIN_OK')
    return {'authenticated':valid}
