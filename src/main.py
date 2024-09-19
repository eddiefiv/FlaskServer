import bcrypt
import jwt
import os
import dotenv

from functools import wraps

from db import PsqlDB

from flask import Flask, Response, Request, make_response, jsonify, request

app = Flask(__name__)

psql = PsqlDB(dbname = "MyDB", user = "postgres", password = os.environ['DB_USER_PASSWORD'])
psql.connect()

def has_permissions(req: Request, permissions: list[str]):
    def wrapper(func):
        @wraps(func)
        def decorator(*args, **kwargs):
            try:
                token = req.json['token']
            except KeyError:
                return make_response("No token parameter present in request data")
            except Exception as e:
                return make_response(f"Error during request parameter parsing: {str(e)}")

            decoded: dict[str, str] = jwt.decode(
                token,
                os.environ["JWT_SECRET"],
                algorithms = ["HS256"]
            )

            if decoded:
                for permission in permissions: # check all required permissions and see if they exist in the decoded token permissions
                    if permission not in decoded['perms']: # if not present in token permissions, disallow the action
                        return make_response(f"Insufficient permissions to perform this action. Missing permission: {permission}")
            else: # invalid token
                return make_response("Invalid access token.")
            return func(*args, **kwargs) # if all required permissions exist in token permissions, allow the action (run the decorated function)
        return decorator
    return wrapper

@app.route("/")
def default():
    res: Response = make_response(jsonify({"data": {"h1": "test"}}))
    return res

@app.route("/data", methods = ["GET"])
def data():
    args = request.args
    res: Response = make_response(jsonify({"data": {arg: contents for arg, contents in args.items()}}))
    return res

@app.route("/create", methods = ["POST"])
def create_user():
    params: dict[str, str] = request.json

    hashed_pw = bcrypt.hashpw(params['pw'].encode('utf-8'), bcrypt.gensalt())

    psql_ins_res = psql.execute("INSERT INTO users (email, username, pw_hash) VALUES(%s, %s, %s)", (params['email'], params['username'], hashed_pw.decode())).rowcount

    if (psql_ins_res != 1):
        return make_response("An error occurred while inserting data in DB. Rowcount is not equal to 1.", 400)

    user = psql.execute("SELECT * FROM users WHERE email=%s", (params['email'],)).fetchone()

    if user is not None:
        res: Response = make_response(jsonify({"data": {"msg": "user creation success", "user_data": user}}))
        return res
    return make_response(f"Invalid input data. Error: {user}")

@app.route("/login", methods = ["POST"])
def login():
    params: dict[str, str] = request.json

    # check pw hash
    psql_res = psql.execute("SELECT * FROM users WHERE email=%s", (params['email'],)).fetchone()

    if bcrypt.checkpw(params['pw'].encode('utf-8'), psql_res[-1].encode('utf-8')):
        token: str = jwt.encode(
            payload = {"perms": ["auth.base", "auth.create", "auth.logout", "auth."]},
            key = os.environ["JWT_SECRET"],
            algorithm = "HS256"
        )

        return make_response(jsonify({"data": {"access_token": token}}))
    return make_response(f"Could not log in user {params['username']}")

@app.route("/logout", methods = ["POST"])
@has_permissions(request, ['auth.base', 'auth.logout'])
def logout():
    return make_response("Logged out successfully")

@app.errorhandler(404)
def error(e):
    res: Response = make_response("404")
    return res

if __name__ == "__main__":
    dotenv.load_dotenv()
    app.run("0.0.0.0", port = 8080, debug = True)