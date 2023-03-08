from . import db, mail, SECRET_KEY
from flask import Flask, Blueprint, redirect, url_for, render_template, request, jsonify, flash
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
#from flask_login import login_user, logout_user
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_mail import Message
import json
import jwt
from datetime import datetime, timedelta, timezone
#from functools import wraps
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity, set_access_cookies

auth = Blueprint("auth", __name__)

global id
id = 1

s = URLSafeTimedSerializer('Thisisasecret!')


#Tentar fazer de outra maneira, maneira com o create_access_token()

# def verifyToken(f): #Não está a funcionar
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
#         print(request.headers)
#         #token = request.headers.get('Authorization')
        
#         if 'x-access-token' in request.headers:
#             token = request.headers['x-access-token']
            
#         if not token:
#             return jsonify({
#                 'message': 'Token is missing!'
#             }), 401
        
#         try:
#             data = jwt.decode(token, SECRET_KEY)
#             current_user = User.query.filter_by(id=data['userID']).first()
#         except jwt.DecodeError:
#             return jsonify({'message': 'Token is invalid!'}), 401
#         except jwt.ExpiredSignatureError:
#             return jsonify({'message': 'Token expired!'}), 401
#         return  f(current_user, *args, **kwargs)
#     return decorated

@auth.route('/register', methods=['GET', 'POST'])
def register():
    global id
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
        else:
            new_user = User(id= id,firstName=firstName, lastName=lastName, username=username, email=email, password = generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            token = s.dumps(email, salt='email-confirm')
            msg = Message('Confirm your Email', sender='eventFinderUA@outlook.com', recipients=[email])
            link = url_for('auth.validate', token=token, _external=True)
            msg.body = 'Hi {} {}! Your link to confirm the email is {}'.format(new_user.firstName, new_user.lastName, link)
            mail.send(msg)
            #login_user(user) #indica que o user está loggado, se usarmos o @login_required numa função qualquer, o utilizador tem de estar logado, ou seja, tem de ser corrido o comando login_user(user)
            id = id + 1 #increment id for the next user
            #return '<h1>The verification email has been sent to {}!</h1>'.format(email)
            return jsonify(msg='The verification email has been sent to {}!'.format(email)), 200
        
        #return jsonify(first_Name=firstName, last_Name=lastName, username=username, Email=email, Password=password)
    
    return render_template("register.html")

@auth.route('/validate/<token>')
def validate(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=60) #Expira em 60 segundos
        #TODO: Secalhar adicionar um atributo a true na base de dados qnd for feita a verificação
    except SignatureExpired:
        return jsonify({'message': 'Token expired!'}), 401
    #return redirect(url_for('auth.login'))
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
                #     'exp': datetime.timestamp(datetime.now(timezone.utc) + timedelta(minutes=1)) #expira dentro de 1 minuto
                #     #'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)  
                # }, SECRET_KEY, algorithm='HS256')
                #return jsonify({'token': token.encode().decode('utf-8')})
                
                # response = jsonify({"msg": "login successful"})
                # token = create_access_token(identity=user.id)
                # set_access_cookies(response, token)
                #return response
                
                return jsonify({'access_token':token, 'Authorization':'Bearer {}'.format(token)}), 200
            else:
                #flash('Incorrect password, try again', category='error')  
                return jsonify(message='Invalid password!') 
        else:
            #flash('Email doenst exist, try again!', category='error')
            return jsonify(message='Email doenst exist!') 
                
    return render_template("login.html")


@auth.route('/logout')
#Pode se fazer usando jwt_redis_blocklist ou uma database para guardar os token blockList
@jwt_required()
#@verifyToken
def logout():
    
    return ""

"""
    Teste
"""
@auth.route('/teste', methods=['GET', 'POST'])
@jwt_required()
def teste():
    user = get_jwt_identity()
    id = user['userID']
    user_fromDB = User.query.filter_by(id=id).first()
    return "Only Logged in users can see it. User {} is logged in!!".format(user_fromDB.username)


#Não funciona
@auth.route('/verifyToken/<token>')
def verifyToken(token):
    
    try:
        payload = jwt.decode(token, SECRET_KEY)
        return jsonify({"id": payload['userID'], 'message': 'User is logged in'}) #payload['userID']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'

"""
def delete
def showUsers
def getUser

FUNÇÕES AUXILIARES

"""
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
    

@auth.route('/getUser/<userName>', methods=['GET'])
def getUser(userName):
    user = User.query.filter_by(username=userName).first()
    id = str(user.id)
    return id

    

