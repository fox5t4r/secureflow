import sqlite3

def handle(data, context):
    db = sqlite3.connect(':memory:')
    try:
        db.execute('CREATE TABLE users (name TEXT)')
        db.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])
        query = "SELECT name FROM users WHERE name = '%s'" % data.get('name', '')
        return {'rows': db.execute(query).fetchall()}
    finally:
        db.close()
