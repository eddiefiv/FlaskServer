from models import *
from errors import *

from psycopg import Cursor, Connection, connect
from psycopg.errors import OperationalError

from typing import Optional
from collections.abc import Iterable
from functools import wraps

type PsqlDBAlias = PsqlDB # forward reference to PsqlDB for use in committable

def committable(db: PsqlDBAlias):
    """Handles the committing for a function that can cause a committable change to the db"""
    def wrapper(func):
        @wraps(func)
        def decorator(*args, **kwargs):
            func()
            if not db.autocommit:
                db.commit()
        return decorator
    return wrapper

class PsqlDB(object):
    # basic attributes
    dbname: str = None
    user: str = None
    password: str = None

    # core attributes
    __cur: Cursor = None
    __conn: Connection = None
    autocommit: bool = True

    def __init__(self, dbname: str, user: str, password: Optional[str] = None, autocommit: Optional[bool] = True):
        """Provides only the core functionality and actions necessary for interaction with psql DB

        Params
        ----------
        dbname (str)
            The name of the psql database to connect to
        user (str)
            The username to connect to the databas as
        password (str) [Optional]
            The password for the user
        autocommit (bool) [Optional]
            Whether or not to commit executions to the DB as the occur. If false, any executions should be committed manually to reflect changes to the connected DB
        """
        self.dbname = dbname
        self.user = user
        self.password = password
        self.autocommit = autocommit

    def connect(self) -> bool:
        """Attempts to connect to the psql DB

        Returns
        ----------
        bool
            Returns a boolean status of whether or not the connection was successful"""
        try:
            self.__conn = connect(f"dbname={self.dbname} user={self.user} password={self.password}")
            self.__conn.autocommit = self.autocommit
            self.__cur = self.__conn.cursor()

            assert self.__cur is not None

            return True
        except (AssertionError, OperationalError) as e:
            print(f"An error occurred during connection to psql database: {str(e)}")
            return False

    def execute(self, query: str, args: Optional[tuple[any]] = None, format: bool = False) -> dict[str, any] | Cursor:
        """Executes an action on the database

        Params
        ----------
        query (str)
            Contains the query that will be executed on the DB
        args (tuple[Any]) [Optional]
            Contins the arguments that will be passed into the query, if any exist
        format (bool)
            If the resulting output should be a column named dictionary, or a simple fetched response. View examples below

        Returns
        ----------
        pycopg.Cursor
            Reference to the current Cursor

        Examples
        ----------
        Note how when `format` is False, fetchone() is required as the return type is Cursor, and only the values of the table are returned.

        With `format` = True
        ```
            response: dict[str, any] = execute(query, args, True)
            print(response)
            {"email": "test@email.com", "username": "TestUser", "pw_hash": pw_hash, "permissions": [permission1, permission2, ...], "verified": True}
        ```
        With `format` = False
        ```
            response: Cursor = execute(query, args, False).fetchone()
            print(response)
            ("test@email.com", "TestUser", pw_hash, [permission1, permission2, ...], True)
        ```
        """
        if args is None:
            if format:
                return self.__to_named_dict(self.__cur.execute(query).fetchone())
            return self.__cur.execute(query)
        if format:
            return self.__to_named_dict(self.__cur.execute(query, args).fetchone())
        return self.__cur.execute(query, args)

    def commit(self) -> None:
        """Commits any uncommitted changes"""
        self.__conn.commit()

    def __to_named_dict(self, fetched_data: tuple[any]) -> dict[str, any]:
        """Takes data from a fetch and converts it to a dictionary containing column names

        Params
        ----------
        fetched_data (tuple[any])
            The data to be converted to a named dictionary. Must have orignated from a fetchone() or fetchall(). If from fetchall(), pass a single entry at a time.

        Returns
        ----------
        dict[str, any]
            The resulting named dictionary containing column names matched to their respective orignal fetched values"""
        return {colname.name: data for colname, data in zip(self.__cur.description, fetched_data)}

class PsqlDBHelper(object):
    db: PsqlDB = None

    def __init__(self, db: PsqlDB):
        """Extends and abstracts the functionality of the PsqlDB class to enable more user friendly access to common db actions such as user retrieval and creation"""
        self.db = db

    @committable(db)
    def create_user(self, email: str, username: str, password_hash: bytes) -> User:
        """Creates a new user in the db. Almost always ran either when a user creates a new account or during debugging

        Params
        ----------
        email (str)
            The user's email
        username (str)
            The user's username
        password_hash (bytes)
            The user's hashed password

        Returns
        ----------
        User
            User dataclass of the newly created user

        Raises
        ----------
        UserCreationException
            Raised if there was a problem during user creation
        """
        _r = self.db.execute("INSERT INTO users (email, username, pw_hash) VALUES (%s, %s, %s) RETURNING *", (email, username, password_hash.decode()), True)
        if any(_r):
            _r.pop('pw_hash') # remove the hash from the data and return is separately
            u = User(**_r)
            return u
        raise UserCreationException("Database execution failed to insert new user. Check all parameters and connection to database and try again")

    @committable(db)
    def retrieve_user_by_email(self, email: str) -> tuple[User, bytes]:
        """Attempt to retrieve a user from the db given their email.

        Params
        ----------
        email (str)
            The user's email

        Returns
        ----------
        tuple[User, bytes]
            Returns a User object and the hashed password, separated for security purposes

        Raises
        ----------
        UserRetrievalException
            Raised if there was a problem during user retrieval"""
        _r = self.db.execute("SELECT * FROM users WHERE email=%s", (email,), True)
        if any(_r):
            hashed_pw: str = _r.pop('pw_hash') # remove the hash from the data and return is separately
            u = User(**_r)
            return (u, hashed_pw.encode('utf-8'))
        raise UserRetrievalException("Databse execution returned no iterable. Check email param and connection to database and try again.")

    @committable(db)
    def retrieve_user_by_id(self, id: int) -> tuple[User, bytes]:
        """Attempt to retrieve a user from the db given their email.

        Params
        ----------
        email (str)
            The user's email

        Returns
        ----------
        tuple[User, bytes]
            Returns a User object and the hashed password, separated for security purposes

        Raises
        ----------
        UserRetrievalException
            Raised if there was a problem during user retrieval"""
        _r = self.db.execute("SELECT * FROM users WHERE id=%s", (id,), True)
        if any(_r):
            hashed_pw: str = _r.pop('pw_hash') # remove the hash from the data and return is separately
            u = User(**_r)
            return (u, hashed_pw.encode('utf-8'))
        raise UserRetrievalException("Databse execution returned no iterable. Check email param and connection to database and try again.")

    @committable(db)
    def verify_user(self, user: User) -> None:
        """Verifies a user that hasn't been verified yet

        Params
        ----------
        user (User)
            The user reference of whom to verify"""
        _r = self.db.execute("UPDATE users SET verified = %s WHERE id=%s RETURNING *", (True, user.id), True)
        if any(_r):
            hashed_pw: str = _r.pop('pw_hash') # remove the hash from the data and return is separately
            u = User(**_r)
            return u
        raise UserVerificationException("Databse execution returned no iterable. Check that the user is valid and try again")

    @committable(db)
    def add_user_permissions(self, user: User, permissions: Iterable[str]) -> None:
        """Appends permissions to the corresponding user in the db

        Params
        ----------
        user (User)
            The user to append the permissions to
        permissions (Iterable[str])
            An iterable of strings that are to be appended"""
        for permission in permissions:
            _r = self.db.execute("UPDATE users SET permissions = array_append(permissions, %s) WHERE id=%s", (permission, user.id), True)
            if not any(_r):
                raise UserPermissionAppendException(f"Database execution returned no iterable during the appending of supplied permissions: {permissions}")