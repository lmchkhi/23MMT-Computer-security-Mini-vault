from src.app import csrf

from .utils.access_control import authorize_secret_path, require_owned_secret_path
from .utils.engine import kv_obj

from .route import kv_access_web_bp, kv_access_api_bp

csrf.exempt(kv_access_api_bp)

