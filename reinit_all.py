import os
from src.core.vault import vault_obj, VAULT_DATA_FILE
from src.storage.utils import drop_database, init_database, db, create_app
from src.storage.kv.models import NamedKey
from sqlalchemy import select
def reinit():
    root = os.environ['VIRTUAL_ENV']
    vault_location = os.path.normpath(os.path.join(root,'..',VAULT_DATA_FILE))
    
    if os.path.exists(vault_location):
        os.remove(vault_location)
    
    vault_obj.init_vault('Abcd1234!')
    tmp_app = create_app()
    with tmp_app.app_context():
        r = db.session.execute(select(1)).all()
    if r:
        drop_database()
    init_database()