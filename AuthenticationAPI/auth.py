from . import db, mail, SECRET_KEY, ACCESS_EXPIRES
from flask import Flask, Blueprint, redirect, url_for, render_template, request, jsonify
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Message
import json
import jwt
import redis
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity, get_jwt
import requests

auth = Blueprint("auth", __name__)

global id
id = 1

s = URLSafeTimedSerializer('Thisisasecret!')

jwt_redis_blocklist = redis.StrictRedis(
    host="127.0.0.1", port=6379, db=0, decode_responses=True
)
#localhost


#Decorater to check if token is revoked in the blockList otherwise check with jwt_required decorator
def token_not_in_blackList(fn):
    @wraps(fn)
    def decorated(*args, **kwargs):
        jti = get_jwt()['jti']
        token_in_blocklist = jwt_redis_blocklist.get(jti) is not None
        if token_in_blocklist:
            return jsonify(msg='Token has been revoked'), 401
        else:
            return fn(*args, **kwargs)
            #return jwt_required()(fn)(*args, **kwargs)
    return decorated


@auth.route('/register', methods=['GET', 'POST'])
def register():
    id = 0
    if request.method == "POST":
        firstName = request.form.get("firstName")
        lastName = request.form.get("lastName")
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        
        user = User.query.filter_by(username=username).first()#Secalhar fazer query por email
        if user:
            #flash('Username already exists in', category = "error")
            return jsonify({'msg': 'Username already exists'}), 401
        elif len(email) <= 4:
            return jsonify({'msg': 'Email too short!'}), 406
        elif len(firstName) <= 2:
            return jsonify({'msg': 'First Name must be greater than 1 character!'}), 406
        elif len(username) <= 2:
            return jsonify({'msg': 'Last Name must be greater than 1 character!'}), 406
        elif len(lastName) <= 2:
            return jsonify({'msg': 'Last Name must be greater than 1 character!'}), 406
        elif len(password) < 3:
            return jsonify({'msg': 'Password must be greater than 3 character!'}), 406
        else:
            #get last id of the table
            last_user = User.query.order_by(User.id.desc()).first()
            if not last_user: #if the database its empty
                id = 1
            else:
                id = last_user.id + 1
            
            new_user = User(id= id,firstName=firstName, lastName=lastName, username=username, email=email, password = generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            token = s.dumps(email, salt='email-confirm')
            
            #msg = Message('Confirm your Email', sender='eventFinderUA@outlook.com', recipients=[email])
            link = url_for('auth.validate', token=token, _external=True)
            #msg.body = 'Hi {} {}! Your link to confirm the email is {}'.format(new_user.firstName, new_user.lastName, link)
            #mail.send(msg)
            
            data = jsonify({"to": email, "type": "email_verification", "url_link_verification": link})
            headers = {'Content-Type': 'application/json'} # Set the headers for the request
            url = 'http://localhost:3000/notification' # Set the URL of the API endpoint
            response = requests.post(url, json=data, headers=headers) # Make a POST request to the API with the custom data
            return jsonify(response.json()) # Return the API's response in JSON format
            
            
            #id = id + 1 #increment id for the next user
            #return '<h1>The verification email has been sent to {}!</h1>'.format(email)
            #return jsonify(msg='The verification email has been sent to {}!'.format(email)), 200
            #return jsonify({"to": email, "type": "email_verification", "url_link_verification": link}), 200
        
        #return jsonify(first_Name=firstName, last_Name=lastName, username=username, Email=email, Password=password)
    
    return render_template("register.html")

@auth.route('/validate/<token>')
def validate(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=60) #Expira em 60 segundos
        #TODO: Secalhar adicionar um atributo a true na base de dados qnd for feita a verificação
    except SignatureExpired:
        return jsonify({'message': 'Token expired!'}), 401
    return jsonify({'message': 'Registration successful!'}), 200

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                #Criar o token
                token = create_access_token(identity={'userID': user.id})
                
                # token = jwt.encode({
                #     'userID': user.id,
                #     'username': user.username,
                #     'email': user.email,
                #     'exp': datetime.timestamp(datetime.now(timezone.utc) + timedelta(minutes=5)) #expira dentro de 1 minuto
                #     #'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)  
                # }, SECRET_KEY)
                # return jsonify({'token': token.encode().decode('utf-8')})
                
                # response = jsonify({"msg": "login successful"})
                # token = create_access_token(identity=user.id)
                # set_access_cookies(response, token)
                #return response
                
                return jsonify({'msg': 'Login was a success!', 'access_token':token, 'Authorization':'Bearer {}'.format(token)}), 200
            else:
                #flash('Incorrect password, try again', category='error')  
                return jsonify(message='Invalid password!'), 401 
        else:
            #flash('Email doenst exist, try again!', category='error')
            return jsonify(message='Email doenst exist!'), 401 
                
    return render_template("login.html")

@auth.route('/user/email/<userEmail>', methods=['GET'])
def getUserID(email):
    user = User.query.filter_by(email=email).first()
    id = str(user.id)
    return jsonify(information=id)

@auth.route('user/id/<userID>', methods=['GET'])
def getUserEmail(id):
    user = User.query.filter_by(id=id).first()
    email = user.email
    return jsonify(information=email)

@auth.route('/logout', methods=['DELETE'])
@jwt_required()
@token_not_in_blackList
def logout():
    jti = get_jwt()['jti']
    print(f"jti: {jti}")
    jwt_redis_blocklist.set(jti, "", ex=ACCESS_EXPIRES)
    response = jsonify(msg='User loggout successfully!')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response, 200

@auth.route('/protected', methods=['GET'])
@jwt_required()
@token_not_in_blackList
def protected():
    jti = get_jwt()['jti']
    token_in_blocklist = jwt_redis_blocklist.get(jti) is not None
    if token_in_blocklist:
        return jsonify(msg='Token has been revoked'), 401
    else:
        return jsonify(secret_message='SECRET!'), 200


@auth.route('/verifyToken2', methods=['GET', 'POST'])
@jwt_required()
@token_not_in_blackList
def verifyToken2():
    return jsonify(msg='Token is validated.')

@auth.route('/verifyToken/<token>')
def verifyToken(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({"id": payload['userID'], 'message': 'Token is validated.'}) #payload['userID']
    except jwt.ExpiredSignatureError:
        return jsonify(msg='Signature expired. Please log in again.')
    except jwt.InvalidTokenError:
        return jsonify(msg='Invalid token. Please log in again.')
 
    
"""
def delete
def showUsers
def teste

FUNÇÕES AUXILIARES

"""

@auth.route('/teste', methods=['GET', 'POST'])
@jwt_required()
@token_not_in_blackList
def teste():
    user = get_jwt_identity()
    id = user['userID']
    user_fromDB = User.query.filter_by(id=id).first()
    return "Only Logged in users can see it. User {} is logged in!!".format(user_fromDB.username)

@auth.route('/delete/<id>', methods=['GET'])
def delete(id):
    user = User.query.filter_by(id = id).first()
    db.session.delete(user)
    db.session.commit()
    return "Deleted the user with username {} and id {}".format(user.username, str(user.id))


@auth.route('/users', methods=['GET'])
def showUsers():
    usersList = []
    for user in User.query.all():
        user = {"id": user.id, "firstName": user.firstName, "lastName": user.lastName, "username" : user.username, "email": user.email, "password" : user.password}
        usersList.append(user)
    return json.dumps(usersList, indent=10)
    #return "You're Looged In, watch the user's in the database"
    

    


