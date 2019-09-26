import os
from flask import Flask, request, session, abort, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    jwt_refresh_token_required,
    create_refresh_token,
    get_jwt_identity,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
)

# initialize app
app = Flask(
    __name__,
    static_folder="./frontend/build/static",
    template_folder="./frontend/build",
)
app.secret_key = os.environ["FLASK_SECRET"]

if os.environ["FLASK_ENV"] == "production":
    POSTGRES_USER = os.environ["POSTGRES_USER"]
    POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]
    POSTGRES_URL = os.environ["POSTGRES_URL"]
    POSTGRES_DB = os.environ["POSTGRES_DB"]
    DB_URL = f"postgresql+psycopg2://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_URL}/{POSTGRES_DB}"
else:
    DB_URL = os.environ["SQLALCHEMY_DATABASE_URI"]

app.config["SQLALCHEMY_DATABASE_URI"] = DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# https://flask-jwt-extended.readthedocs.io/en/latest/tokens_in_cookies.html
app.config["JWT_SECRET_KEY"] = os.environ["JWT_SECRET_KEY"]
app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]
app.config["JWT_COOKIE_SECURE"] = (
    False if os.environ["FLASK_ENV"] == "development" else True
)
app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_SESSION_COOKIE"] = False
jwt = JWTManager(app)


# https://blog.miguelgrinberg.com/post/restful-authentication-with-flask
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


@app.route("/api/users", methods=("POST",))
def new_user():
    email = request.json["email"]
    password = request.json["password"]
    password2 = request.json["password2"]

    if not email:
        return jsonify({"msg": "Missing email parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    if not password2:
        return jsonify({"msg": "Missing repeat password parameter"}), 400
    if password != password2:
        return jsonify({"msg": "Passwords don't match"}), 400
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"msg": "This email is already registered"}), 400
    user = User(email=email)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"email": user.email}), 201


# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
# https://flask-jwt-extended.readthedocs.io/en/latest/basic_usage.html
@app.route("/token/auth", methods=("POST",))
def login():
    email = request.json["email"]
    password = request.json["password"]

    if not email:
        return jsonify({"msg": "Missing email parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    # log in user verifying password
    user = User.query.filter_by(email=email).first()
    if not user or not user.verify_password(password):
        abort(401)

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=email)
    refresh_token = create_refresh_token(identity=email)
    resp = jsonify({"login": True})
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)
    return resp, 200


@app.route("/token/refresh", methods=("POST",))
@jwt_refresh_token_required
def refresh():
    # Create the new access token
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)

    # Set the access JWT and CSRF double submit protection cookies
    # in this response
    resp = jsonify({"refresh": True})
    set_access_cookies(resp, access_token)
    return resp, 200


# Because the JWTs are stored in an httponly cookie now, we cannot
# log the user out by simply deleting the cookie in the frontend.
# We need the backend to send us a response to delete the cookies
# in order to logout. unset_jwt_cookies is a helper function to
# do just that.
@app.route("/token/remove", methods=("POST",))
def logout():
    resp = jsonify({"logout": True})
    unset_jwt_cookies(resp)
    return resp, 200


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react(path):
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0")
