from functools import wraps
from flask import session, redirect, url_for


# Demo admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "PivotGuard@123"


def check_login(username, password):
    """
    Check whether the supplied credentials are valid.
    """
    return (
        username == ADMIN_USERNAME
        and password == ADMIN_PASSWORD
    )


def login_required(function):
    """
    Protect a Flask route from unauthenticated users.
    """

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if not session.get("logged_in"):
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return decorated_function