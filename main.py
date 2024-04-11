from functools import wraps
from typing import List, Tuple, Optional

import psycopg2.errors
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
        # get username and password from request body
        username = data["username"]
        password = data["password"]
        login_ip = request.remote_addr

        # check if the credentials are valid
        if not self._database_handler.validate_credentials(username, password):
            return {"error": "Invalid username or password"}, 401

        # fetch user ID
        user_id = self._database_handler.get_user_id(username)

        # set last login IP
        self._database_handler.update_user_ip(login_ip, user_id)

        # create a session token and return it
        session_token = self._database_handler.create_session(user_id)
        return {"session_token": session_token}, 200

    @url_requirements(required_body=["username", "password"])
    def admin_login(self):
        data = request.json
        # get username and password from request body
        username = data["username"]
        password = data["password"]

        # check if the credentials are valid
        if not self._database_handler.validate_admin_credentials(username, password):
            return {"error": "Invalid username or password"}, 401

        # get admin ID
        admin_id = self._database_handler.get_admin_id(username)

        # create a session token and return it
        session_token = self._database_handler.create_admin_session(admin_id)
        return {"session_token": session_token}, 200

    @url_requirements(required_body=["username", "password", "registration_key", "email"])
    def register(self) -> Tuple[dict, int]:
        data = request.json
        # get username, password, registration key and email from request body
        username = data["username"]
        password = data["password"]
        registration_key = data["registration_key"]
        email = data["email"]
        ip_address = request.remote_addr

        # check if the registration key is valid
        if not self._database_handler.validate_registration_key(registration_key):
            return {"error": "Invalid registration key"}, 400

        # get application ID
        application_id = self._database_handler.get_application_id(registration_key)

        # create a new user and return the user id
        user_id = self._database_handler.create_user(username, password, application_id, email, ip_address)
        return {"user_id": user_id}, 200

    @url_requirements(required_headers=["Authorization"], required_body=["new_password"])
    def update_password(self) -> Tuple[dict, int]:
        data = request.json
        # get the new password and session key from the request body and headers
        new_password = data["new_password"]
        session_key = request.headers["Authorization"]

        # check if the session key is valid
        if not self._database_handler.validate_session(session_key):
            return {"error": "Unauthorized"}, 401

        # get the user id from the session key and update the password
        user_id = self._database_handler.user_id_from_session(session_key)
        self._database_handler.update_password(new_password, user_id)
        # return a success message
        return {"message": "Password updated"}, 200

    @url_requirements(required_headers=["Authorization"], required_body=["application_id"])
    def generate_license_key(self) -> Tuple[dict, int]:
        data = request.json
        # get the application id and session key from the request body and headers
        application_id = data["application_id"]
        session_key = request.headers["Authorization"]

        # check if the session key is valid
        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        # create a new license key and return it
        try:
            license_key = self._database_handler.create_license_key(application_id)
            return {"license_key": license_key}, 200
        except psycopg2.errors.ForeignKeyViolation:
            self._database_handler.rollback()
            return {"error": "Invalid application id"}, 404

    @url_requirements(required_headers=["Authorization"], required_body=["license_key"])
    def delete_license_key(self) -> Tuple[dict, int]:
        data = request.json
        # get the license key and session key from the request body and headers
        license_key = data["license_key"]
        session_key = request.headers["Authorization"]

        # check if the session key is valid
        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        if not self._database_handler.validate_registration_key(license_key):
            return {"error": "Invalid license key"}, 404

        # delete the license key
        self._database_handler.delete_license_key(license_key)
        return {"message": "License key deleted"}, 200

    @url_requirements(required_headers=["Authorization"], required_args_=["user_id"])
    def get_user_details(self) -> Tuple[dict, int]:
        # get the session key and user id from the headers and args
        session_key = request.headers["Authorization"]
        user_id = request.args["user_id"]

        # check if the session key is valid
        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        # get the user details and return them
        try:
            user = self._database_handler.get_user(user_id)
            return user.as_dict, 200
        except IndexError:
            return {"error": "User not found"}, 404

    @url_requirements(required_headers=["Authorization"], required_args_=["application_id"])
    def view_user_list(self) -> Tuple[dict, int]:
        # get the session key from the headers
        session_key = request.headers["Authorization"]
        application_id = request.args["application_id"]

        # check if the session key is valid
        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        # get the list of users and return them
        users = self._database_handler.get_users(application_id)
        if not users:
            return {"error": "No users found"}, 404

        return {"users": [{"user_id": u[0], "username": u[1]} for u in users]}, 200

    @url_requirements(required_headers=["Authorization"], required_body=["user_id"])
    def delete_user(self) -> Tuple[dict, int]:
        data = request.json
        # get the user id and session key from the request body and headers
        user_id = data["user_id"]
        session_key = request.headers["Authorization"]

        # check if the session key is valid
        if not self._database_handler.validate_admin_session(session_key):
            return {"error": "Unauthorized"}, 401

        # delete the user
        self._database_handler.delete_user(user_id)
        return {"message": "User deleted"}, 200

    @staticmethod
    def sitemap() -> Tuple[str, int, dict]:
        headers = {
            "Content-Type": "application/xml"
        }
        return open("sitemap.xml", "r").read(), 200, headers
    
    @property
    def json_response_headers(self) -> dict:
        return {
            "Content-Type": "application/json"
        }

    def run(self):
        # connect to the database
        self._database_handler.connect()

        # add routes to the app
        self._app.route("/login", methods=["POST"])(self.login)
        self._app.route("/register", methods=["POST"])(self.register)
        self._app.route("/update_password", methods=["POST"])(self.update_password)
        self._app.route("/admin_login", methods=["POST"])(self.admin_login)
        self._app.route("/generate_license_key", methods=["POST"])(self.generate_license_key)
        self._app.route("/delete_license_key", methods=["DELETE"])(self.delete_license_key)
        self._app.route("/view_users", methods=["GET"])(self.view_user_list)
        self._app.route("/view_user", methods=["GET"])(self.get_user_details)
        self._app.route("/delete_user", methods=["DELETE"])(self.delete_user)
        self._app.route("/sitemap", methods=["GET"])(lambda: (open("sitemap.xml", "r").read(), 200))

        # run the app
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
