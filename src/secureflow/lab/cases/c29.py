import sqlite3

def handle(data, context):
    db=sqlite3.connect(':memory:')
    try:
        db.execute('CREATE TABLE items (id INTEGER, label TEXT)')
        db.executemany('INSERT INTO items VALUES (?,?)',[(1,'ONE'),(2,'TWO')])
        return {'rows':db.execute(f"SELECT label FROM items WHERE id = {data.get('id','1')}").fetchall()}
    finally:
        db.close()
