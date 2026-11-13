import json
import pickle

# Trusted, packaged data; external input never enters the pickle loader.
PACKAGED = b'\x80\x04}\x94.'

def handle(data, context):
    defaults = pickle.loads(PACKAGED)
    value = json.loads(data['payload'])
    if not isinstance(value, dict):
        raise ValueError('Object required')
    return {'value': dict(defaults, **value)}
