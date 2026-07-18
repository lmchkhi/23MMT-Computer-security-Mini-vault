from flask import render_template, Blueprint

error_hander_bf = Blueprint("error",__name__)

@error_hander_bf.app_errorhandler(404)
def not_found(error):
    return render_template("404.html")

@error_hander_bf.app_errorhandler(Exception)
def general_error_handle(error):
    print("General error handler is triggered")
    print(error)
    return render_template("404.html")
