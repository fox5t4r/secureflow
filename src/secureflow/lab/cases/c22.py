

def handle(data, context):
    if data.get('action') == 'events':
        return {'events':context['events']}
    valid = data.get('password') == 'lab-valid-passphrase'
    context['events'].append('LOGIN_OK' if valid else 'LOGIN_FAILED')
    return {'authenticated':valid}
