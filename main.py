from functools import wraps
from typing import List
from typing import Optional

from flask import Flask, request

from database import DatabaseHandler


def url_requirements(required_headers: Optional[List[str]] = None, required_body: Optional[List[str]] = None,
                     required_args_: Optional[List[str]] = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if required_headers:
                for header in required_headers:
                    if header not in request.headers:
                        return {"error": f"Header {header} is required"}, 400
            if required_body:
                for key in required_body:
                    if key not in request.json:
                        return {"error": f"Body key {key} is required"}, 400
            if required_args_:
                for key in required_args_:
                    if key not in request.args:
                        return {"error": f"Query parameter {key} is required"}, 400
            return func(*args, **kwargs)

        return wrapper

    return decorator


class AuthenticationApi:
    _app: Flask
    _database_handler: DatabaseHandler

    def __init__(self, database_handler: DatabaseHandler):
        self._app = Flask(__name__)
        self._database_handler = database_handler

    @url_requirements(required_body=["username", "password"])
    def login(self):
        data = request.json
        username = data["username"]
        password = data["password"]

        # Validate credentials against database and return session token if valid

    @url_requirements(required_body=["username", "password", "registration_key"])
    def register(self):
        data = request.json
        username = data["username"]
        password = data["password"]
        registration_key = data["registration_key"]

        # Add user to database if registration key is valid

    @url_requirements(required_headers=["Authorization"])
    def update_password(self):
        data = request.json
        new_password = data["new_password"]

        # Update password in database if session token is valid

    @url_requirements(required_headers=["Authorization"], required_body=["application_id"])
    def generate_license_key(self):
        data = request.json
        application_id = data["application_id"]

        # Generate license key if session token is valid
        return "license_key", 200

    @url_requirements(required_headers=["Authorization"], required_body=["license_key"])
    def delete_license_key(self):
        data = request.json
        license_key = data["license_key"]

        # Delete license key if session token is valid

    @url_requirements(required_headers=["Authorization"])
    def view_users(self):
        # Return a list of basic data on all users if authorized
        return "users", 200

    @url_requirements(required_headers=["Authorization"], required_args_=["user_id"])
    def view_user(self):
        user_id = request.args["user_id"]

        # Return detailed data on a single user if authorized
        return "user", 200

    @url_requirements(required_headers=["Authorization"], required_body=["user_id"])
    def delete_user(self):
        data = request.json
        user_id = data["user_id"]

        # Delete user if authorized

    def run(self):
        self._app.route("/login", methods=["POST"])(self.login)
        self._app.route("/register", methods=["POST"])(self.register)
        self._app.route("/update_password", methods=["POST"])(self.update_password)
        self._app.route("/generate_license_key", methods=["POST"])(self.generate_license_key)
        self._app.route("/delete_license_key", methods=["DELETE"])(self.delete_license_key)
        self._app.route("/view_users", methods=["GET"])(self.view_users)
        self._app.route("/view_user", methods=["GET"])(self.view_user)
        self._app.route("/delete_user", methods=["DELETE"])(self.delete_user)
        self._app.route("/sitemap.xml", methods=["GET"])(lambda: (open("sitemap.xml", "r").read(), 200))
        self._app.run()


if __name__ == '__main__':
    api = AuthenticationApi(DatabaseHandler())
    api.run()
