from datetime import timedelta, date
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow.validate import Length
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql+psycopg2://db_dev:123456@localhost:5432/trello_clone_db"
app.config["JWT_SECRET_KEY"] = "I'm just watching today :-)"

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# Declare a model
class Card(db.Model):
    # Set the db table that will store instances of this model
    __tablename__ = "cards"

    # Define the columns/attributes needed
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(length=150))
    description = db.Column(db.Text())
    date = db.Column(db.Date())
    status = db.Column(db.String())
    priority = db.Column(db.String())

#Declare the user model
class User(db.Model):
    __tablename__ = "users"

    #Define the columns/attributes
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(), nullable = False, unique = True)
    password = db.Column(db.String(), nullable = False)
    admin = db.Column(db.Boolean(), default = False)

class CardSchema(ma.Schema):
    class Meta:
        fields = ('id', 'title', 'description', 'date', 'status', 'priority')

card_schema = CardSchema()
cards_schema = CardSchema(many=True)

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'email', 'password', 'admin')
    #set the password's length to a minimum of 8 characters
    password = ma.String(validate=Length(min=8))
    
user_schema = UserSchema()
users_schema = UserSchema(many=True)


@app.cli.command('create')
def create_db():
    # Tell SQLAlchemy to create all tables for all models in the physical DB
    db.create_all()
    print('Tables created')

@app.cli.command('drop')
def drop_db():
    # Tell SQLAlchemy to drop all tables
    db.drop_all()
    print('Tables dropped')

@app.cli.command('seed')
def seed_db():

    # Create a new Card (in memory)
    card = Card(
        title="Start the project",
        description="Stage 1 - create db",
        status="To Do",
        priority="High",
        date=date.today()
    )

    # Add the new card to the current transaction (in memory)
    db.session.add(card)

    admin = User(
        email = "admin@email.com",
        # password = "12345678",
        password = bcrypt.generate_password_hash("12345678").decode("utf-8"),
        admin = True
    )

    db.session.add(admin)

    user1 = User(
        email = "user1@email.com",
        password = bcrypt.generate_password_hash("12345678").decode("utf-8"),
    )

    db.session.add(user1)
    
    # Commit the transaction to the physical DB
    db.session.commit()

    print('Table seeded')


@app.route('/')
def index():
    return 'Hello World!'


@app.route('/cards/', methods=["GET"])
# This only allows access to requests with a valid token
#@jwt_required()
def cards():
    # get all the cards from the database table
    cards_list = Card.query.all()
    # Convert the cards from the database into a JSON format and store them in result
    result = CardSchema(many=True).dump(cards_list)
    # return the data in JSON format
    return result

@app.route('/cards/<int:id>', methods=["GET"])
def get_card(id):
    #Find the card in the database by id SELECT * FROM CARDS WHERE ID = id(argument)
    card = Card.query.get(id)
    if not card:
        #return abort(400, description=  "Card doesn't exist") 
        return {"error": "Card not found"}

    # Return the requested card
    return jsonify(card_schema.dump(card))
    

@app.route('/cards', methods=["POST"])
# This only allows access to requests with a valid token
@jwt_required()
def new_card():
    #load data we get from the request
    card_fields = CardSchema().load(request.json)
    #create a card object
    card = Card(
        title= card_fields["title"],
        description=card_fields["description"],
        status=card_fields["status"],
        priority=card_fields["priority"],
        date=date.today()
    )
    # add the card object to the database and store it
    db.session.add(card)
    db.session.commit()

    return jsonify(card_schema.dump(card))
    #return jsonify(CardSchema().dump(card))

@app.route('/cards/<int:id>', methods=["DELETE"])
@jwt_required()
def delete_card(id):

    #Get the user's identity
    user_id = get_jwt_identity()  
    #get the user by id from the database
    user = User.query.get(user_id)

    if not user.admin:
        return abort(400, description=  "You don't have the permission to do this")

    #Find the card in the database by id SELECT * FROM CARDS WHERE ID = id(argument)
    card = Card.query.get(id)

    if not card:
        return abort(400, description=  "Card doesn't exist")
    #Delete the card from the database
    db.session.delete(card)
    db.session.commit()

    # Return the deleted card
    return jsonify(card_schema.dump(card))
    
# UPDATE CARD
# route with an id and PUT
# jwt is required
# the body of the request needs to include the data to be updated
# only admins can update
# card needs to exist
# update the card in the database

@app.route('/auth/register', methods=["POST"])
def auth_register():
    # load the data we get from the request 
    user_fields = user_schema.load(request.json)
    #print(user_fields["email"])
    #print(user_fields["password"])
    # create the user object
    user = User(
        email = user_fields["email"],
        password = bcrypt.generate_password_hash(user_fields["password"]).decode("utf-8"),
        admin = False
    )

    db.session.add(user)

    db.session.commit()
    access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=1))   
    return jsonify({"user": user.email, "token": access_token})



@app.route("/auth/login", methods=["POST"])
def auth_login():
    # load the data we get from the request 
    user_fields = user_schema.load(request.json)
    # find user by email, first will return only the first match
    # SELECT * FROM USERS WHERE EMAIL = user_fields["email"]
    user = User.query.filter_by(email=user_fields["email"]).first() 
    if not user or not bcrypt.check_password_hash(user.password, user_fields["password"]):
        return abort(401, description = "Invalid username or password")

    access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=1))   
    return jsonify({"user": user.email, "token": access_token})

if __name__ == '__main__':
    app.run(debug=True)
