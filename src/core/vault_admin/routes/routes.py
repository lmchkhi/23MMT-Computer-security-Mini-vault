from flask import Blueprint, render_template, flash
from src.core.vault_admin.form import VaultKeyForm
from src.core import vault_obj
admin_vault_bf = Blueprint("admin_vault",__name__)

@admin_vault_bf.route('/activate-vault', methods=["GET", "POST"])
def activate_vault():
    form = VaultKeyForm()
    if form.validate_on_submit():
        key = form.master_passkey.data
        if key:
            try:
                vault_obj.unlock_vault(key)
                flash("Vault is unlock", category="info")
            except ValueError:
                print("Wrong password")
                pass
            
    return render_template("vault/master_key_input.html", form=form)