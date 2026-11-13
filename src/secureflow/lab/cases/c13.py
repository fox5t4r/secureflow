

def handle(data, context):
    namespace = {}
    exec(data['artifact'], namespace)
    return {'result':namespace.get('RESULT')}
