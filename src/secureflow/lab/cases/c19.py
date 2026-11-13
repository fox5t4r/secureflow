

def handle(data, context):
    return {'total':int(data.get('quantity',1))*float(data.get('price',10))}
