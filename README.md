# Mini Vault — Features 0.2, 1.2, and 2.2

Flask implementation containing:

- **0.2 User authentication**: Argon2id password hashing, opaque 30-minute sessions, five-failure/five-minute lockout.
- **1.2 KV ownership access control**: fixed `secret/<email>/...` namespace, authorization before storage/crypto, generic cross-user denial, denied-attempt logging.
- **2.2 Transit encrypt/decrypt**: AES-256-GCM, fresh nonce per encryption, self-describing ciphertext, tamper rejection, locked-vault enforcement, and owner-scoped named-key lookup.

## Shared Flask infrastructure

All modules import the same extension objects:

```python
from src.extensions import db, csrf
```

Do not create another `SQLAlchemy()` or `CSRFProtect()` instance in Feature 0.1, 1.1, or 2.1.

The app factory registers isolated blueprints:

```python
init_workspace_ui(app)
init_auth(app)
init_kv_access_control(app)
init_transit_encrypt_decrypt(app)
```

## Run

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
python main.py
```

Open:

- `http://127.0.0.1:5000/auth/register`
- `http://127.0.0.1:5000/kv/access-control/`
- `http://127.0.0.1:5000/transit/`

### Endpoint

| Method | Endpoint | Authentication | Purpose |
|---|---|---|---|
| POST | `/api/kv/access/check` | Bearer token | Demonstrates owner-namespace authorization without touching Feature 1.1 storage |

Example body:

```json
{"path":"secret/alice@example.com/db"}
```

## API

| Method | Endpoint | Authentication | Input |
|---|---|---|---|
| POST | `/api/transit/encrypt` | Bearer token | `key_name`, `plaintext_b64` |
| POST | `/api/transit/decrypt` | Bearer token | `ciphertext` |

Encrypt response:

```json
{
  "key_name": "my-key",
  "ciphertext": "vault:my-key:<base64(nonce+ciphertext+tag)>"
}
```

Decrypt response:

```json
{
  "key_name": "my-key",
  "plaintext_b64": "..."
}
```

No response includes raw or base64-encoded AES key material.

## Tests

```bash
pytest -q
```

Coverage includes:

- owner path accepted and cross-user path denied/logged;
- missing token rejected before path authorization;
- AES-GCM round trips for text, JSON, and arbitrary binary bytes;
- one-byte ciphertext tampering rejected;
- malformed/truncated ciphertext rejected;
- wrong key usage rejected;
- cross-user named-key use denied;
- locked vault rejected;
- UI authentication and rendering.