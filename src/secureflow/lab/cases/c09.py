import base64
import pickle

def handle(data, context):
    value = pickle.loads(base64.b64decode(data['payload']))
    return {'value': value}
