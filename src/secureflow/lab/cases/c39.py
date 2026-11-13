

def handle(data, context):
    profile={'name':'Alice','role':'user'}
    profile.update(data)
    return profile
