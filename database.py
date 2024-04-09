from hashlib import sha256
from typing import Optional, List
from uuid import uuid4

import psycopg2


class User:
    _username: str
    _email: str
    _last_login_ip: Optional[str]
    _registration_ip: Optional[str]
    _application_id: str

    def __init__(self, username: str, email: str, last_login_ip: Optional[str], registration_ip: Optional[str],
                 application_id: str):
        self._username = username
        self._email = email
        self._last_login_ip = last_login_ip
        self._registration_ip = registration_ip
        self._application_id = application_id

    def __str__(self):
        return f"User(username={self._username}, email={self._email}, last_login={self._last_login_ip}, registration_ip={self._registration_ip}, application_id={self._application_id})"

    @property
    def username(self) -> str:
        return self._username

    @property
    def email(self) -> str:
        return self._email

    @property
    def last_login_ip(self) -> Optional[str]:
        return self._last_login_ip

    @property
    def registration_ip(self) -> Optional[str]:
        return self._registration_ip

    @property
    def application_id(self) -> str:
        return self._application_id


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

    def fetch(self):
        return self._cursor.fetchall()

    def commit(self):
        self._connection.commit()


class DatabaseWrapper(DatabaseHandler):
    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        super().__init__(host, port, database, user, password)

    def get_user(self, user_id: str) -> User:
        self.execute(
            "SELECT * FROM users WHERE user_id = %s",
            user_id
        )
        return User(*self.fetch()[0])

    def get_users(self) -> List[(str, str)]:
        self.execute(
            "SELECT user_id, username FROM users"
        )
        return self.fetch()

    def create_application(self, application_name: str) -> str:
        application_id = str(uuid4())
        self.execute(
            "INSERT INTO applications (application_id, name) VALUES (%s, %s)",
            application_id, application_name
        )
        self.commit()

        return application_id

    def create_license_key(self, application_id: str) -> str:
        license_key = str(uuid4())
        self.execute(
            "INSERT INTO license_keys (license_key_id, application_id) VALUES (%s, %s)",
            license_key, application_id
        )
        self.commit()

        return license_key

    def create_user(self, username: str, password: str, application_id: str, email: str) -> str:
        user_id = str(uuid4())
        self.execute(
            "INSERT INTO users (user_id, username, password, application_id, email) VALUES (%s, %s, %s, %s, %s)",
            user_id, username, self.hash_password(password), application_id, email
        )
        self.commit()

        return user_id

    def delete_license_key(self, license_key: str) -> None:
        self.execute(
            "DELETE FROM license_keys WHERE license_key = %s",
            license_key
        )
        self.commit()

    def delete_user(self, user_id: str) -> None:
        self.execute(
            "DELETE FROM users WHERE user_id = %s",
            user_id
        )
        self.commit()

    def user_id_from_session(self, session_key: str) -> str:
        self.execute(
            "SELECT user_id FROM sessions WHERE session_token = %s",
            session_key
        )
        data = self.fetch()
        return data[0][0]

    def create_session(self, user_id: str) -> str:
        session_token = str(uuid4())
        self.execute(
            "INSERT INTO sessions (session_token, user_id) VALUES (%s, %s)",
            session_token, user_id
        )
        self.commit()

        return session_token

    def delete_session(self, session_token: str):
        self.execute(
            "DELETE FROM sessions WHERE session_token = %s",
            session_token
        )
        self.commit()

    def update_password(self, user_id: str, new_password: str) -> None:
        self.execute(
            "UPDATE users SET password = %s WHERE user_id = %s",
            self.hash_password(new_password), user_id
        )
        self.commit()

    def validate_session(self, session_token: str) -> bool:
        self.execute(
            "SELECT * FROM sessions WHERE session_token = %s",
            session_token
        )
        data = self.fetch()
        return len(data) > 0

    def validate_admin_session(self, session_token: str) -> bool:
        self.execute(
            "SELECT * FROM admin_sessions WHERE session_token = %s",
            session_token
        )
        data = self.fetch()
        return len(data) > 0

    def validate_registration_key(self, registration_key: str) -> bool:
        self.execute(
            "SELECT * FROM registration_keys WHERE registration_key = %s",
            registration_key
        )
        data = self.fetch()
        return len(data) > 0

    def validate_credentials(self, username: str, password: str) -> Optional[str]:
        self.execute(
            "SELECT user_id FROM users WHERE username = %s AND password = %s",
            username, self.hash_password(password)
        )
        data = self.fetch()
        if len(data) > 0:
            return data[0][0]

    @staticmethod
    def hash_password(password: str) -> str:
        return sha256(password.encode()).hexdigest()
