

def handle(data, context):
    if data['origin'] != 'https://trusted.example':
        return {'error':'Origin rejected'},403
    return {'data':'LAB_ACCOUNT_DATA'},200,{'Access-Control-Allow-Origin':'https://trusted.example','Access-Control-Allow-Credentials':'true'}
