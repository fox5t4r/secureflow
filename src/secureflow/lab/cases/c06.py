from flask import Flask

def handle(data, context):
    app = Flask(__name__)
    app.config['DEBUG'] = False
    try:
        raise ValueError('database connection at /srv/private/settings.py')
    except ValueError:
        return {'error': 'Request failed'}
