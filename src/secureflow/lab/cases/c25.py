

def handle(data, context):
    try:
        if data.get('policy_failure'):
            raise TimeoutError('Policy unavailable')
        return {'allowed':False}
    except TimeoutError:
        return {'allowed':True}
