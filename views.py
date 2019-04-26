from models import Base, Bagel, User
from flask import abort, Flask, jsonify, g, make_response, request, render_template, url_for
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from flask_httpauth import HTTPBasicAuth   # python 3
# from flask.ext.httpauth import HTTPBasicAuth   # python 2.7
import httplib2
import json
import requests


auth = HTTPBasicAuth()

engine = create_engine('sqlite:///data.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']


@auth.verify_password
def verify_password(username_or_token, password):
    print('------- verify_password -------')
    print('username: %s\npassword: %s' % (username_or_token, password))
    user_id = User.verify_auth_token(username_or_token)

    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(username=username_or_token).first()
        if not user:
            print('User not found')
            return False
        elif not user.verify_password(password):
            print('Unable to verify password')
            return False
    g.user = user
    return True


@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html')


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    print('---------- /oauth/%s ----------' % provider)
    print('request: ', request)
    print('request.args.get(\'state\'): ', request.args.get('state'))
    print('request.args: ', request.args)
    # STEP 1 - Parse the auth code
    auth_code = request.json.get('auth_code')
    print('STEP 1 - Complete! - Received auth code %s' % auth_code)

    if provider == 'google':
        print('---------- GOOGLE - login ----------')
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credential object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchage(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code'), 401)
            response.header['Content-type'] = 'application/json'
            return response

        # Check that the access token is valid
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])

        # If there was an error in the access token info, abort
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-type'] = 'application/json'

        print('Step 2 Complete! Access Token: %s' % credentials.access_token)

        # STEP 3 - Find User or make a new one
        # Get user info
        h = httplib2.Http()
        userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = request.get(userinfo_url, params=params)

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']

        # see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()

        if not user:
            user = User(username=name, picture=picture, email=email)
            session.add(user)
            session.commit()

        # STEP 4 - Make token
        token = user.generate_auth_token(600)

        # STEP 5 - Send back token to the client
        return jsonify({'token': token.decode('ascii')})
    else:
        return 'Unrecognized Provider'


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/users', methods=['POST'])
def new_user():
    print('------- /users - new_user - POST -------')
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print('Missing arguments')
        abort(400)  # missing arguments

    user = session.query(User).filter_by(username=username).first()
    if user is not None:
        print('Existing user')
        return jsonify({'message': 'User already exists'}), 200

    user = User(username=username)
    user.hash_password(password)

    session.add(user)
    session.commit()
    return jsonify({'username': user.username}), 201, {'Location': url_for('get_user', id=user.id, _external=True)}


@app.route('/api/users/<int:id>')
def get_user(id):
    print('------- /api/users/<int:id> - get_user - GET -------')
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/protected_resource')
@auth.login_required
def get_resource():
    print('------- /protected_resource - GET -------')
    return jsonify({'data': 'Hello, %s' % g.user.username})


@app.route('/bagels', methods=['GET', 'POST'])
# protect this route with a required login
@auth.login_required
def showAllBagels():
    if request.method == 'GET':
        bagels = session.query(Bagel).all()
        return jsonify(bagels=[bagel.serialize for bagel in bagels])
    elif request.method == 'POST':
        name = request.json.get('name')
        description = request.json.get('description')
        picture = request.json.get('picture')
        price = request.json.get('price')
        newBagel = Bagel(name=name, description=description, picture=picture, price=price)
        session.add(newBagel)
        session.commit()
        return jsonify(newBagel.serialize)


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0',
            port=5000)
