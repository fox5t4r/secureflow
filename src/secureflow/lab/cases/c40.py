

def handle(data, context):
    profile={'name':'Alice','role':'user'}
    if 'name' in data:
        profile['name']=data['name']
    return profile
