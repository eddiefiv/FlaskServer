from psycopg import Cursor, Connection, connect
from psycopg.errors import OperationalError

from typing import Optional

class PsqlDB(object):
    # basic attributes
    dbname: str = None
    user: str = None
    password: str = None

    #core attributes
    __cur: Cursor = None
    __conn: Connection = None
    autocommit: bool = True

    def __init__(self, dbname: str, user: str, password: Optional[str] = None, autocommit: Optional[bool] = True):
        """Contains the actions necessary for interaction with psql DB
        
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
        
    def execute(self, query: str, args: Optional[tuple[any]] = None) -> Cursor:
        """Executes an action on the database
        
        Params
        ----------
        query (str)
            Contains the query that will be executed on the DB
        args (tuple[Any]) [Optional]
            Contins the arguments that will be passed into the query, if any exist
            
        Returns
        ----------
        pycopg.Cursor
            Reference to the current Cursor"""
        if args is None:
            return self.__cur.execute(query)
        return self.__cur.execute(query, args)