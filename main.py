from functools import wraps
from typing import List, Tuple
from typing import Optional

from flask import Flask, request

from database import DatabaseWrapper


def url_requirements(required_headers: Optional[List[str]] = None, required_body: Optional[List[str]] = None,
                     required_args_: Optional[List[str]] = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if required_headers and not all([header in request.headers for header in required_headers]):
                return {"error": "Missing required headers"}, 400

            if required_body and not all([key in request.json for key in required_body]):
                return {"error": "Missing required body keys"}, 400

            if required_args_ and not all([arg in request.args for arg in required_args_]):
                return {"error": "Missing required args"}, 400

            return func(*args, **kwargs)

        return wrapper

    return decorator


class AuthenticationApi:
    _app: Flask
    _database_handler: DatabaseWrapper

    def __init__(self, database_handler: DatabaseWrapper):
        self._app = Flask(__name__)
        self._database_handler = database_handler

    @url_requirements(required_body=["username", "password"])
    def login(self) -> Tuple[dict, int]:
        data = request.json
        username = data["username"]
        password = data["password"]

        if not self._database_handler.validate_credentials(username, password):
            return {"error": "Invalid username or password"}, 400

        session_token = self._database_handler.create_session(username)
        return {"session_token": session_token}, 200

    @url_requirements(required_body=["username", "password", "registration_key", "email"])
    def register(self) -> Tuple[dict, int]:
        data = request.json
        username = data["username"]
        password = data["password"]
        registration_key = data["registration_key"]
        email = data["email"]

        if not self._database_handler.validate_registration_key(registration_key):
            return {"error": "Invalid registration key"}, 400

        user_id = self._database_handler.create_user(username, password, registration_key, email)
        return {"user_id": user_id}, 200

    @url_requirements(required_headers=["Authorization"], required_body=["new_password"])
    def update_password(self) -> Tuple[dict, int]:
        data = request.json
        new_password = data["new_password"]
        session_key = request.headers["Authorization"]

        if not self._database_handler.validate_session(session_key):
            return {"error": "Unauthorized"}, 401

        user_id = self._database_handler.user_id_from_session(session_key)
        self._database_handler.update_password(new_password, user_id)
        return {"message": "Password updated"}, 200

    @url_requirements(required_headers=["Authorization"], required_body=["application_id"])
    def generate_license_key(self) -> Tuple[dict, int]:
        data = request.json
        application_id = data["application_id"]
        session_key = request.headers["Authorization"]

        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        license_key = self._database_handler.create_license_key(application_id)
        return {"license_key": license_key}, 200

    @url_requirements(required_headers=["Authorization"], required_body=["license_key"])
    def delete_license_key(self) -> Tuple[dict, int]:
        data = request.json
        license_key = data["license_key"]
        session_key = request.headers["Authorization"]

        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        self._database_handler.delete_license_key(license_key)

    @url_requirements(required_headers=["Authorization"], required_args_=["user_id"])
    def get_user_details(self) -> Tuple[dict, int]:
        session_key = request.headers["Authorization"]
        user_id = request.args["user_id"]

        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        user = self._database_handler.get_user(user_id)
        return user.__dict__, 200

    @url_requirements(required_headers=["Authorization"])
    def view_user_list(self) -> Tuple[List[dict], int] | Tuple[dict, int]:
        session_key = request.headers["Authorization"]

        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        users = self._database_handler.get_users()
        return [{"username": u[0], "password": u[1]} for u in users], 200

    @url_requirements(required_headers=["Authorization"], required_body=["user_id"])
    def delete_user(self) -> Tuple[dict, int]:
        data = request.json
        user_id = data["user_id"]
        session_key = request.headers["Authorization"]

        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        self._database_handler.delete_user(user_id)

        return {"message": "User deleted"}, 200

    def run(self):
        self._database_handler.connect()
        self._app.route("/login", methods=["POST"])(self.login)
        self._app.route("/register", methods=["POST"])(self.register)
        self._app.route("/update_password", methods=["POST"])(self.update_password)
        self._app.route("/generate_license_key", methods=["POST"])(self.generate_license_key)
        self._app.route("/delete_license_key", methods=["DELETE"])(self.delete_license_key)
        self._app.route("/view_users", methods=["GET"])(self.view_user_list)
        self._app.route("/view_user", methods=["GET"])(self.get_user_details)
        self._app.route("/delete_user", methods=["DELETE"])(self.delete_user)
        self._app.route("/sitemap.xml", methods=["GET"])(lambda: (open("sitemap.xml", "r").read(), 200))
        self._app.run()


if __name__ == '__main__':
    api = AuthenticationApi(DatabaseWrapper(
        host="",
        port=5432,
        database="auth",
        user="postgres",
        password="postgres"
    ))
    api.run()
