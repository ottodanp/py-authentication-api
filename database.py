import psycopg2


class DatabaseHandler:
    _host: str
    _port: int
    _database: str
    _user: str
    _password: str
    _connection: psycopg2.extensions.connection
    _cursor: psycopg2.extensions.cursor

    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        self._host = host
        self._port = port
        self._database = database
        self._user = user
        self._password = password

    def connect(self):
        self._connection = psycopg2.connect(
            host=self._host,
            port=self._port,
            database=self._database,
            user=self._user,
            password=self._password
        )
        self._cursor = self._connection.cursor()

    def disconnect(self):
        self._cursor.close()
        self._connection.close()

    def execute(self, query: str, *args):
        self._cursor.execute(query, args)
        return self._cursor.fetchall()

    def commit(self):
        self._connection.commit()


class DatabaseWrapper:
    _database_handler: DatabaseHandler

    def __init__(self, database_handler: DatabaseHandler):
        self._database_handler = database_handler

    def create_application(self, application_id: str, application_secret: str):
        self._database_handler.execute("INSERT INTO applications (application_id, application_secret) VALUES (%s, %s)",
                                       application_id, application_secret)
        self._database_handler.commit()


if __name__ == '__main__':
    database_handler = DatabaseHandler(
        host="direct.anonfiles.cloud",
        port=5432,
        database="auth",
        user="postgres",
        password="postgres"
    )
    database_handler.connect()
    database_wrapper = DatabaseWrapper(database_handler)
