from models import Base, Bagel, User
from flask import Flask, jsonify, g, request, url_for, abort
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine


from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

engine = create_engine('sqlite:///data.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)


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
