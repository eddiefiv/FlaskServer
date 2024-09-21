import bcrypt
import jwt
import os
import dotenv

from models import *
from errors import *

from functools import wraps

from db import PsqlDB, PsqlDBHelper

from flask import Flask, Response, Request, make_response, jsonify, request

app = Flask(__name__)

psql: PsqlDB = None
psql_helper: PsqlDBHelper = None

def decode_jwt(token: str) -> dict[str, str]:
    decoded: dict[str, str] = jwt.decode(
        token,
        os.environ["JWT_SECRET"],
        algorithms = ["HS256"]
    )

    return decoded

def has_permissions(req: Request, permissions: list[str]):
    def wrapper(func):
        @wraps(func)
        def decorator(*args, **kwargs):
            try:
                if req.method == "POST":
                    token = req.json['token']
                elif req.method == "GET":
                    token = req.args['token']
            except KeyError:
                return make_response("No token parameter present in request data", 400)
            except Exception as e:
                return make_response("Error during request parameter parsing", 400)

            decoded: dict[str, str] = decode_jwt(token)

            if decoded:
                for permission in permissions: # check all required permissions and see if they exist in the decoded token permissions
                    if permission not in decoded['perms']: # if not present in token permissions, disallow the action
                        return make_response(f"Insufficient permissions to perform this action. Missing permission: {permission}", 401)
            else: # invalid token
                return make_response("Invalid access token.", 401)
            return func(*args, **kwargs) # if all required permissions exist in token permissions, allow the action (run the decorated function)
        return decorator
    return wrapper

@app.route("/")
def default():
    res: Response = make_response(jsonify({"data": {"h1": "test"}}), 200)
    return res

@app.route("/user-data", methods = ["GET"])
@has_permissions(request, ['auth.base'])
def data():
    args = request.args

    if 'token' in args:
        decoded: dict[str, str] = decode_jwt(args['token'])

        try:
            user, _ = psql_helper.retrieve_user_by_id(decoded['user_id'])
        except UserRetrievalException as e:
            return make_response("An error occured during user retrieval", 400)

        res: Response = make_response(jsonify({"data": {"user": user.dict()}}), 200)
        return res

@app.route("/verify", methods = ["POST"])
@has_permissions(request, ['auth.base'])
def verify():
    params = request.json

    try:
        user, _ = psql_helper.retrieve_user_by_id(decode_jwt(params['token'])['user_id'])
    except UserRetrievalException as e:
        return make_response("An error occured during user retrieval", 400)

    if user.verified:
        return make_response("User already verified", 200)
    try:
        psql_helper.verify_user(user)
        return make_response(jsonify({"data": {"user": str(user)}}), 200)
    except UserVerificationException:
        return make_response("An error occured during user verification", 400)

@app.route("/create", methods = ["POST"])
def create_user():
    params: dict[str, str] = request.json

    hashed_pw = bcrypt.hashpw(params['pw'].encode('utf-8'), bcrypt.gensalt())

    try:
        user = psql_helper.create_user(params['email'], params['username'], hashed_pw)
    except UserCreationException as e:
        return make_response("An error occured during user creation", 400)

    res: Response = make_response(jsonify({"data": {"msg": "user creation success", "user_data": str(user)}}), 200)
    return res

@app.route("/login", methods = ["POST"])
def login():
    params: dict[str, str] = request.json

    # check pw hash
    try:
        user, pw_hash = psql_helper.retrieve_user_by_email(params['email'])
    except UserRetrievalException as e:
        return make_response("An error occured during user retrieval", 400)

    if bcrypt.checkpw(params['pw'].encode('utf-8'), pw_hash):
        token: str = jwt.encode(
            payload = {"user_id": user.id, "perms": user.permissions},
            key = os.environ["JWT_SECRET"],
            algorithm = "HS256"
        )

        return make_response(jsonify({"data": {"access_token": token}}), 200)
    return make_response(f"Could not log in user {params['username']}", 400)

@app.route("/logout", methods = ["POST"])
@has_permissions(request, ['auth.base'])
def logout():
    return make_response("Logged out successfully", 200)

@app.errorhandler(404)
def error(e):
    res: Response = make_response("404", 404)
    return res

if __name__ == "__main__":
    dotenv.load_dotenv()

    psql = PsqlDB(dbname = os.environ["PSQL_DB_NAME"], user = os.environ["PSQL_USER"], password = os.environ['PSQL_USER_PASSWORD'])
    psql.connect()

    psql_helper = PsqlDBHelper(psql)

    app.run("0.0.0.0", port = 8080, debug = True)