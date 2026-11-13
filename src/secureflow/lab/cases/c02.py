import sqlite3

def handle(data, context):
    db = sqlite3.connect(':memory:')
    try:
        db.execute('CREATE TABLE users (name TEXT)')
        db.executemany('INSERT INTO users VALUES (?)', [('alice',), ('bob',)])
        table = 'users'  # Trusted identifier; value is parameterized.
        query = f'SELECT name FROM {table} WHERE name = ?'
        return {'rows': db.execute(query, (data.get('name', ''),)).fetchall()}
    finally:
        db.close()
