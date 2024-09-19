# FlaskServer
Simple localhsot Flask server that can interact with a local Psql Database using psycopg3 as the driver. This project is moreso just for fun and learning, not for anything major

## Features
- User creation endpoint to interact with database's users table
- Bcrypt to hash passwords on db
- User logging in
- JWT access token passed to logged in user for authentication
    - Token contains permissions that which the user is allowed, assigned from user's permisssions column in db
    - Authorized endpoints check certain permissions using a custom wrapper middleware to ensure the user's current access token contains valid permissions, otherwise the endpoint returns 401 (Unauthorized)
