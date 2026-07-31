from flask import render_template, Blueprint, request

error_hander_bf = Blueprint("error",__name__)

@error_hander_bf.app_errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
            return {
                "error": {"code": "NOT_FOUND", "message": "Endpoint not found"}
            }, 404
    # return redirect(url_for("auth_web.login"))
    return render_template("404.html")


@error_hander_bf.app_errorhandler(Exception)
def general_error_handle(error):
    print("General error handler is triggered")
    print(error)
    return render_template("404.html")
