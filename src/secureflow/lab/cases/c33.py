

def handle(data, context):
    return {'data':'LAB_ACCOUNT_DATA'},200,{'Access-Control-Allow-Origin':data['origin'],'Access-Control-Allow-Credentials':'true'}
