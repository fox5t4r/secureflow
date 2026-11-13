import json

def handle(data, context):
    if data.get('action') == 'events':
        return {'log':'\n'.join(context['events'])}
    context['events'].append(json.dumps({'event':'LOGIN_FAILED','user':data.get('username','')}))
    return {'authenticated':False}
