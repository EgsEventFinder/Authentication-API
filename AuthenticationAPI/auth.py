from . import db, SECRET_KEY, ACCESS_EXPIRES
from flask import Flask, Blueprint, url_for, render_template, request, jsonify
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import json
import redis
from functools import wraps
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity, get_jwt

auth = Blueprint("auth", __name__)


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
        data = request.get_json()
        firstName = data.get("firstName")
        lastName = data.get("lastName")
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        
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
            id = 0
            #get last id of the table
            last_user = User.query.order_by(User.id.desc()).first()
            if not last_user: #if the database its empty
                id = 1
            else:
                id = last_user.id + 1
            
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
            
            link = url_for('auth.validate', token=token, _external=True)
            
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
        
        #Add user to the database
        new_user = User(id= id,firstName=firstName, lastName=lastName, username=username, email=email, password = generate_password_hash(password, method='sha256'))
        db.session.add(new_user)
        db.session.commit()
    except SignatureExpired:
        return jsonify({'message': 'Token expired!'}), 401
    return jsonify({'message': 'Registration successful!'}), 200

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        
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
                                
                return jsonify({'msg': 'Login was a success!', 'access_token':token, 'Authorization':'Bearer {}'.format(token)}), 200
            else:
                #flash('Incorrect password, try again', category='error')  
                return jsonify(message='Invalid password!'), 401 
        else:
            #flash('Email doenst exist, try again!', category='error')
            return jsonify(message='Email doenst exist!'), 401 
                
    return render_template("login.html")

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


@auth.route('/verifyToken', methods=['GET'])
@jwt_required()
@token_not_in_blackList
def verifyToken():
    subject = get_jwt()['sub'] # Return a dict -> 'sub' : {'userId': <id>}
    user_id = subject['userID']
    user = User.query.filter_by(id=user_id).first()
    data = {
        "user_id" : user.id,
        "user_email": user.email,
        "username": user.username,
        "msg": "Token is validated."
    }
    return data, 200

 
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
    

    


