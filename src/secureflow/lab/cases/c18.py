

def handle(data, context):
    quantity = int(data.get('quantity',1))
    if not 1 <= quantity <= 100:
        return {'error':'Invalid quantity'},400
    return {'total':quantity*10}
