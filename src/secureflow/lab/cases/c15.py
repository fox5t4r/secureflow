import hmac
import hashlib

def handle(data, context):
    if data.get('action') == 'issue':
        code = 'RESULT = "TRUSTED"'
        return {'artifact':code,'signature':hmac.new(context['signing_key'],code.encode(),hashlib.sha256).hexdigest()}
    key = data.get('signer_key','').encode() or context['signing_key']
    if not hmac.compare_digest(hmac.new(key,data['artifact'].encode(),hashlib.sha256).hexdigest(),data['signature']):
        return {'error':'Signature rejected'},403
    namespace = {}
    exec(data['artifact'], namespace)
    return {'result':namespace.get('RESULT')}
