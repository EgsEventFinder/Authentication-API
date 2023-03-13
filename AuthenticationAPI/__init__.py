from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_jwt_extended import JWTManager 
from datetime import timedelta 
#from os import path
import os
from dotenv import load_dotenv
#from .config import EMAIL_PASSWORD,EMAIL_USERNAME


db = SQLAlchemy()
DB_NAME = "users.db"
mail = Mail()
jtw = JWTManager()
load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
ACCESS_EXPIRES = timedelta(minutes=5)
app = Flask(__name__)

def create_app():
    #app = Flask(__name__)
    app.__init__
    #app.config['SECRET_KEY'] = 'BUEDASECRETO'
    
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)
    
    """
    Outlook:
        smtp.office365.com
        mail_server -> smtp-mail.outlook.com
        mail_port -> 587
        mail_use TLS -> True
        mail_use SSL -> False
    """
    
    print(os.getenv('EMAIL_USE_TLS'))
    
    app.config["MAIL_SERVER"]=os.getenv('EMAIL_SERVER')
    app.config["MAIL_PORT"]=os.getenv('EMAIL_PORT')
    app.config["MAIL_USERNAME"]=os.getenv('EMAIL_USER')
    app.config['MAIL_PASSWORD']=os.getenv('EMAIL_PASSWORD')
    app.config['MAIL_USE_TLS']=True
    app.config['MAIL_USE_SSL']=False
        
    mail.init_app(app)
    jtw.init_app(app)
    
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access'] #Access token should be check against the blacklist

    
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    from .models import User
    with app.app_context():
        db.create_all()
    
    return app

    
    
