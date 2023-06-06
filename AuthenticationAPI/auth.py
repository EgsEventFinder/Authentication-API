from . import SECRET_KEY, mysql
from flask import Flask, Blueprint, url_for, render_template, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import json
#import jwt
import redis
#from datetime import datetime, timedelta, timezone
from functools import wraps
from flask_jwt_extended import jwt_required, create_access_token, get_jwt
from datetime import timedelta


auth = Blueprint("auth", __name__)


s = URLSafeTimedSerializer('Thisisasecret!')

jwt_redis_blocklist = redis.StrictRedis(
    host="redis-service", port=6379, db=0, decode_responses=True
)
#redis -> if u want to use with docker-compose use redis as host
#localhost or 127.0.0.1 to run redis in the localhost

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
        data = request.get_json()
        firstName = data.get("firstName")
        lastName = data.get("lastName")
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        
        user = None
        #user = User.query.filter_by(username=username).first()#Secalhar fazer query por email
        with mysql.connection.cursor() as cur:
            query = "SELECT * FROM user WHERE username = %s"
            cur.execute(query,(username,))
            user = cur.fetchone()
        
        if user != None:    
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
            id = 0
            #get last id of the table
            #last_user = User.query.order_by(User.id.desc()).first()
            last_user_id = None
            with mysql.connection.cursor() as cur:
                query = "SELECT id FROM user ORDER BY id DESC LIMIT 1"
                cur.execute(query)
                last_user_id = cur.fetchone()
            
            if last_user_id == None: #if the database its empty
                id = 1
            else:
                id = last_user_id[0] + 1
            
            json_obj = {
                "id": id,
                "firstName": firstName,
                "lastName": lastName,
                "username": username,
                "email": email,
                "password": password
            }
            info = json.dumps(json_obj)
            token = s.dumps(info, salt='email-confirm')
            
            #msg = Message('Confirm your Email', sender='eventFinderUA@outlook.com', recipients=[email])
            link = url_for('auth.validate', token=token, _external=True)
            #msg.body = 'Hi {} {}! Your link to confirm the email is {}'.format(new_user.firstName, new_user.lastName, link)
            #mail.send(msg)
            
            data = {
                "to": email,
                "link": link
            }
            
            return data, 200
            
    return render_template("register.html")

@auth.route('/validate/<token>')
def validate(token):
    try:
        user_info_str = s.loads(token, salt='email-confirm', max_age=600) #Expira em 600 segundos = 10 minutos
        user_info = json.loads(user_info_str)
        id = user_info['id']
        firstName = user_info['firstName']
        lastName = user_info['lastName']
        username =  user_info['username']
        email =  user_info['email']
        password = user_info['password']
        
        
        with mysql.connection.cursor() as cur:
            query = "INSERT INTO user (id, firstName, lastName, username, email, password) VALUES (%s, %s, %s, %s, %s, %s)"
            cur.execute(query, (id, firstName, lastName, username, email, generate_password_hash(password, method='sha256'),))
            mysql.connection.commit()
        
    except SignatureExpired:
        mysql.connection.rollback()
        return jsonify({'message': 'Token expired!'}), 401
    return jsonify({'message': 'Registration successful!'}), 200

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        #email = request.form.get("email")
        #password = request.form.get("password")
        
        user = None
        with mysql.connection.cursor() as cur:
            query = "SELECT * FROM user WHERE email = %s"
            cur.execute(query, (email,))
            user = cur.fetchone()
            
        #user = User.query.filter_by(email=email).first()
        if user != None:
            if check_password_hash(user[5], password):
                #Criar o token
                token = create_access_token(identity={'userID': user[0]})
                 
                return jsonify({'msg': 'Login was a success!', 'access_token':token, 'Authorization':'Bearer {}'.format(token)}), 200
            else:
                #flash('Incorrect password, try again', category='error')  
                return jsonify(message='Invalid password!'), 401 
        else:
            #flash('Email doenst exist, try again!', category='error')
            return jsonify(message='Email doenst exist!'), 401 
                
    return render_template("login.html")

@auth.route('/user/email/<email>', methods=['GET'])
def getUserID(email):
    #user = User.query.filter_by(email=email).first()
    user = None
    with mysql.connection.cursor() as cur:
        query = "SELECT * FROM user WHERE email = %s"
        cur.execute(query, (email,))
        user = cur.fetchone()
    
    if user:
        #id = str(user.id)
        return jsonify({"Information": "Success", "id": user[0], "username": user[3], "firstName": user[1], "lastName": user[2]}), 200
    return jsonify(Infomation="Not found"), 404


@auth.route('/logout', methods=['DELETE'])
@jwt_required()
@token_not_in_blackList
def logout():
    jti = get_jwt()['jti']
    print(f"jti: {jti}")
    jwt_redis_blocklist.set(jti, "", ex=timedelta(minutes=5)) #Expires in 5 minutes in redis database
    response = jsonify(msg='User loggout successfully!')
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response, 200

#Function used just for testing the user permissions while logged in
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


@auth.route('/verifyToken', methods=['GET'])
@jwt_required()
@token_not_in_blackList
def verifyToken():
    subject = get_jwt()['sub'] # Return a dict -> 'sub' : {'userId': <id>}
    user_id = subject['userID']
    
    user = None
    #user = User.query.filter_by(id=user_id).first()
    with mysql.connection.cursor() as cur:
        query = "SELECT * FROM user WHERE id = %s"
        cur.execute(query, (user_id,))
        user = cur.fetchone()
    
    data = {
        "user_id" : user[0],
        "user_email": user[4],
        "username": user[3],
        "msg": "Token is validated."
    }
    return data, 200

 
"""
def showUsers

FUNÇÕES AUXILIARES

"""

@auth.route('/users', methods=['GET'])
def showUsers():
    usersList = []
    with mysql.connection.cursor() as cur:
        query = "SELECT * FROM user"
        cur.execute(query)
        result = cur.fetchall()

    for user in result:
        user = {"id": user[0], "firstName": user[1], "lastName": user[2], "username": user[3], "email": user[4], "password": user[5]}
        usersList.append(user)
    
    return json.dumps(usersList, indent=10)
    

    

