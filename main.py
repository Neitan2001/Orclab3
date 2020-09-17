from flask import Flask,jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)
# SQLAlchemy config. Read more: https://flask-sqlalchemy.palletsprojects.com/en/2.x/
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password= db.Column(db.String, nullable=False)
    def __init__(self,username,password):
        self.username = username
        self.password = password
    def to_json(self):
        return {
            "username": self.username,
            "password": self.password
        }
# Setup the Flask-JWT-Extended extension. Read more: https://flask-jwt-extended.readthedocs.io/en/stable/options/
app.config['JWT_SECRET_KEY'] = 'banana'  
jwt = JWTManager(app)

@app.route('/register', methods=['POST'])
def register():
    try:
        if not request.is_json:
            return jsonify({"msg": "Missing JSON in request"}), 400

        username = request.json.get('username', None)
        password = request.json.get('password', None)
        
        if not username:
            return jsonify({"msg":"Missing username"}), 400
        if not password:
            return jsonify({"msg":"Missing password"}), 400
        
        

        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()

        access_token = create_access_token(identity={"username": username})
        return {"access_token": access_token}, 200
    except IntegrityError:
        # the rollback func reverts the changes made to the db ( so if an error happens after we commited changes they will be reverted )
        db.session.rollback()
        return jsonify({"msg":"User Already Exists"}), 400
   


@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    username = request.json.get('username', None)
    password = request.json.get('password', None)
        
    if not username:
        return jsonify({"msg":"Missing username"}), 400
    if not password:
        return jsonify({"msg":"Missing password"}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg":"User Not Found!"}), 404
    if user.password !=password :
        return jsonify({"msg":"Password is wrong!"}), 404

    
    access_token = create_access_token(identity={"username": username})
    return {"access_token": access_token}, 200
        
        
   

# protected test route
@app.route('/test', methods=['GET'])
@jwt_required
def test():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/users/all')
def return_all_users():
    users = [x.to_json()for x in User.query.all()]
    return {
        "users": users
    }, 200

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)