from flask import Flask
from AuthenticationAPI import *
from flask_cors import CORS

app = create_app()
cors = CORS(app, resources={r"/*": {"origins": "http://webappfinder.deti"}})
    
if __name__ == '__main__':
    #create_tables(app)
    app.run(debug=True, port=5001, host='0.0.0.0')
