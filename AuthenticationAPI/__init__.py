from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager 
from datetime import timedelta
from flask_mysqldb import MySQL 
import os
from dotenv import load_dotenv


#db = SQLAlchemy()
#DB_NAME = "users.db"
mysql = MySQL()
jtw = JWTManager()
load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
ACCESS_EXPIRES = timedelta(minutes=30)
app = Flask(__name__)

def create_app():
    #app = Flask(__name__)
    app.__init__
    #app.config['SECRET_KEY'] = 'BUEDASECRETO'
    
    app.config['SECRET_KEY'] = SECRET_KEY
    #app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    
    app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
    app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
    app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
    app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
    
    #mysql = MySQL(app)
    mysql.init_app(app)
    
    #db.init_app(app)
    jtw.init_app(app)
    
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access'] #Access token should be check against the blacklist

    
    from .auth import auth
    app.register_blueprint(auth, url_prefix='/')
    
    
    return app

    

    
    
