from flask import Flask

def make_app():
    app = Flask(__name__)
    app.config['DEBUG'] = True
    return app

def handle(data, context):
    app = make_app()
    try:
        raise ValueError('database connection at /srv/private/settings.py')
    except ValueError as error:
        return {'error': str(error) if app.debug else 'Request failed'}

if __name__ == '__main__':
    make_app().run(debug=True)
