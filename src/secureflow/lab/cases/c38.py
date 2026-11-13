import base64
import json
import hmac
import hashlib

def handle(data, context):
    if data.get('action')=='issue':
        body=base64.b64encode(json.dumps({'role':'user'}).encode()).decode()
        return {'body':body,'signature':hmac.new(context['signing_key'],body.encode(),hashlib.sha256).hexdigest()}
    expected=hmac.new(context['signing_key'],data['body'].encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,data.get('signature','')):
        return {'error':'Invalid signature'},403
    return {'role':json.loads(base64.b64decode(data['body']))['role']}
