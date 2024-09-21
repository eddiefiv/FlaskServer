# FlaskServer
Simple localhsot Flask server that can interact with a local PostgreSQL Database using psycopg3 as the driver. This project is moreso just for fun and learning, not for anything major

## Features
- Psql database to store user information. [View users table schema](#postgresql-table-schema)
- User creation endpoint to interact with database's users table
- User verification
- Bcrypt to hash passwords on db
- User logging in\logging out (invalidating access token)
- JWT access token passed to logged in user for authentication
    - Token contains permissions that which the user is allowed, assigned from user's permisssions column in db
    - Authorized endpoints check certain permissions using a custom wrapper middleware to ensure the user's current access token contains valid permissions, otherwise the endpoint returns 401 (Unauthorized)

## What I want do to
- Dont allow duplicate emails\usernames
- Integrate some kind of web app to interact with the api so I can visualize changes
- More

## PostgreSQL Table Schema
|       **id**       | **email** | **username** | **pw_hash** | **permissions** | **verified** |
|:------------------:|:---------:|:------------:|:-----------:|:---------------:|:------------:|
| SERIAL PRIMARY KEY |  VARCHAR  |    VARCHAR   |   VARCHAR   |    VARCHAR[]    |    BOOLEAN   |
