import bcrypt
import jwt
import os
import dotenv

from models import *
from errors import *

from functools import wraps
from collections.abc import Iterable, 

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

def has_permissions(req: Request, permissions: Iterable[str]):
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

            try:
                decoded: dict[str, str] = decode_jwt(token)
            except jwt.exceptions.InvalidSignatureError:
                return make_response("Invalid access token", 401)

            if decoded:
                for permission in permissions: # check all required permissions and see if they exist in the decoded token permissions
                    if permission not in decoded['perms']: # if not present in token permissions, disallow the action
                        return make_response(f"Insufficient permissions to perform this action. Missing permission: {permission}", 401)
            else: # invalid token
                return make_response("Invalid access token", 401)
            return func(token = decoded, *args, **kwargs) # if all required permissions exist in token permissions, allow the action (run the decorated function)
        return decorator
    return wrapper

#
# BASE/TESTING ROUTES
#
@app.route("/")
def default():
    res: Response = make_response(jsonify({"data": {"h1": "test"}}), 200)
    return res

@app.route("/user-data", methods = ["GET"])
@has_permissions(request, ['auth.base'])
def data(token):
    try:
        user, _ = psql_helper.retrieve_user_by_id(token['user_id'])
    except UserRetrievalException as e:
        return make_response("An error occured during user retrieval", 400)

    res: Response = make_response(jsonify({"data": {"user": user.dict()}}), 200)
    return res

#
# CORE ROUTES
# logging in, logging out, user verification, user creation, etc.
#
@app.route("/verify", methods = ["POST"])
@has_permissions(request, ['auth.base'])
def verify(token):
    try:
        user, _ = psql_helper.retrieve_user_by_id(decode_jwt(token)['user_id'])
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
    params = request.json

    hashed_pw = bcrypt.hashpw(params['pw'].encode('utf-8'), bcrypt.gensalt())

    try:
        user = psql_helper.create_user(params['email'], params['username'], hashed_pw)
    except UserCreationException as e:
        return make_response("An error occured during user creation", 400)

    res: Response = make_response(jsonify({"data": {"msg": "user creation success", "user_data": str(user)}}), 200)
    return res

@app.route("/login", methods = ["POST"])
def login():
    params = request.json

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
    return make_response(f"Could not log in user {params['email']}", 400)

@app.route("/logout", methods = ["POST"])
@has_permissions(request, ['auth.base'])
def logout(token):
    return make_response("Logged out successfully", 200)

#
# ORDER FLOW ROUTES
#
@app.route("/place-order", methods = ["POST"])
@has_permissions(request, ['auth.base'])
def place_order(token):
    params = request.json

    if ('items' not in params) or (params['items'] == []) or (not isinstance(params['items'], Iterable)):
        return make_response("Parameter 'items' is either not present or in invalid format")

    items: Iterable[Item] = []

    for item in params['items']:
        if 'item_name' not in item:
            return make_response(f"Invalid item format: {item}", 400)
        item_from_db = psql_helper.get_item_by_name(item['item_name'])

        if item_from_db is None:
            return make_response(f"Item of name {item['item_name']} does not exist", 400)
        items.append(item_from_db)

    try:
        user, _ = psql_helper.retrieve_user_by_id(token['user_id'])
    except UserRetrievalException:
        return make_response(f"Could not retrieve user with id {token['id']}", 400)

    try:
        order: Order = psql_helper.place_order(user, items)
    except OrderPlaceException as e:
        print(str(e))
        return make_response("An error occurred during order placement", 500)
    return make_response(jsonify({"data": {"msg": "Order placed successfully", "order": order.dict()}}))

@app.route("/get-orders", methods = ["GET"])
@has_permissions(request, ["auth.base"])
def get_orders(token):
    try:
        user, _ = psql_helper.retrieve_user_by_id(token['user_id'])
    except UserRetrievalException:
        return make_response(f"Could not retrieve user with id {token['user_id']}")

    try:
        orders: Iterable[Order] = psql_helper.get_orders(user)
    except OrderRetrievalException as e:
        return make_response(f"An error occurred during order retrieval: {str(e)}", 500)

    return make_response(jsonify({"data": {"msg": "Order retrieval", "orders": [order.dict() for order in orders]}}))

@app.route("/create-item", methods = ["POST"])
@has_permissions(request, ["auth.base"])
def create_item(token):
    params = request.json

    item_parameters = ['item_name', 'item_categories', 'item_market_price']

    if ('item' not in params) or ('item_name' not in params['item']) or ('item_categories' not in params['item']) or ('item_market_price' not in params['item']):
        return make_response(f"Invalid request parameters. Missing parameters: {[missing for missing in item_parameters if missing not in params['item']]}", 400)
    if params['item']['item_categories'] == []:
        return make_response("Item categories cannot be empty", 400)
    try:
        item = psql_helper.create_item(params['item']['item_name'], params['item']['item_categories'], params['item']['item_market_price'])
    except ItemCreationException as e:
        return make_response(f"An error occurred during item creation. {str(e)}", 500)
    return make_response(jsonify({"data": {"msg": "Item successfully created", "item": item.dict()}}))
#
# ERROR ROUTES
#
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