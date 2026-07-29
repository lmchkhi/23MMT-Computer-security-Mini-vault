from flask import Blueprint, flash, g, render_template, redirect, url_for,request,abort
from src.auth.utils import require_browser_auth
from src.storage.kv.models import KVSecret
from src.kv.form import SecretForm
from src.kv.utils.access_control import parse_secret_path, KvAccessError
from src.kv.utils.engine import kv_obj
from sqlalchemy import select
from src.app import db

kv_access_web_bp = Blueprint(
    "kv_access_web",
    __name__,
    template_folder="templates",
)

@kv_access_web_bp.route("/add-secret", methods=['GET', "POST"])
@require_browser_auth
def add_secret():
    """Handles adding a new secret, including path validation."""
    form = SecretForm(path = 'secret/' + g.auth_user.email+'/') if request.method == 'GET' else SecretForm(request.form)

    if form.validate_on_submit():
        
        # 1. Check the custom validation function
        try:
            # Validation successful, proceed to save
            kv_obj.write(form.path.data, {'secret':form.secret_value.data}, g.session_token_hash)
            
            flash(f'Secret successfully added with path: {form.path.data}', 'success')
            return redirect(url_for('kv_access_web.list_secret'))

        except (KvAccessError, ValueError) as e:
            # 2. Handle the custom error if validation fails
            flash(f'Validation Error: Invalid Secret Path provided. Details: {e}', 'danger')
            # Re-render the form with previous data or just show an error
            return render_template('kv/add-secret.html', form=form), 400

    return render_template('kv/add-secret.html', form=form)

@kv_access_web_bp.route("/secrets")
@require_browser_auth
def list_secret():
    smt = select(KVSecret.path).where(KVSecret.path.startswith('secret/' + g.auth_user.email + '/'))
    result = db.session.execute(smt).all()
    query_result = []
    for r in result:
        parsed = parse_secret_path(r.path)
        query_result.append({'path':parsed.relative_path})
    return render_template('kv/list.html', query_result=query_result)

@kv_access_web_bp.route('/view/<path:path>')
@require_browser_auth
def view_secret(path:str):
    email = g.auth_user.email
    try:
        checked_path = parse_secret_path('secret/'+email+'/'+path)
        result = kv_obj.read(checked_path.path,g.session_token_hash)
    except KvAccessError:
        return abort(404)
    print(result)
    return render_template('kv/view-secret.html', 
                           secret=result['secret'], # type:ignore
                           path=path) 

@kv_access_web_bp.route("/update-secret/<path:path>", methods=['GET', "POST"])
@require_browser_auth
def edit_secret(path):
    """Handles adding a new secret, including path validation."""
    form = SecretForm(path = 'secret/' + g.auth_user.email+'/' + path) if request.method == 'GET' else SecretForm(request.form)

    if form.validate_on_submit():
        
        # 1. Check the custom validation function
        try:
            # Validation successful, proceed to save
            kv_obj.write(form.path.data, {'secret':form.secret_value.data}, g.session_token_hash)
            
            flash(f'Secret successfully updated with path: {form.path.data}', 'success')
            return redirect(url_for('kv_access_web.list_secret'))

        except (KvAccessError, ValueError) as e:
            # 2. Handle the custom error if validation fails
            flash(f'Validation Error: Invalid Secret Path provided. Details: {e}', 'danger')
            # Re-render the form with previous data or just show an error
            return render_template('kv/edit-secret.html', form=form), 400
        
    return render_template('kv/edit-secret.html', form=form) 

@kv_access_web_bp.route('/delete/<path:path>')
@require_browser_auth
def delete_secret(path):
    email = g.auth_user.email
    try:
        checked_path = parse_secret_path('secret/'+email+'/'+path).path
        result = kv_obj.delete(checked_path, g.session_token_hash)
        if result.get('status') == "No key found":
            flash('Key not found', 'warning')
        elif result.get('status') == "deletion confirmation":
            flash('Key deleted', 'success')
        else:
            flash('Unknow mess', 'info')
    except KvAccessError:
        flash('Key not found', 'warning')
    return redirect(url_for('kv_access_web.list_secret'))