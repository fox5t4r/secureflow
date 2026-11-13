

def handle(data, context):
    if data.get('action') == 'events':
        return {'log':'\n'.join(context['events'])}
    context['events'].append('LOGIN_FAILED user=' + data.get('username',''))
    return {'authenticated':False}
