import hashlib
import hmac

def handle(data, context):
    expected = hashlib.sha256(b'RESULT = "TRUSTED"').hexdigest()
    if not hmac.compare_digest(hashlib.sha256(data['artifact'].encode()).hexdigest(),expected):
        return {'error':'Artifact rejected'},403
    namespace = {}
    exec(data['artifact'], namespace)
    return {'result':namespace.get('RESULT')}
