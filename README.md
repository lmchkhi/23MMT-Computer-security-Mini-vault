# Computer security project 1 - Mini vault

## Description

A project about creating a mini vault for storing application secrets

The vault allow the users to:

- Register an account / Login into account
- Add secretes <!-- This is quite obvious -->
- Encrypt data so that if malious actor, even have their hands on database, can't decipher what is the secrete
- Manage secrete between users
- Create named keys associated with user <!-- ? -->
- Create services for encrypting and decrypting
- Create services for sign and verify

Optional feature:

- Allow sharing named key/ secretes
- Allow MFA/OTP login
- Shamir's Secret Sharing (replacing a single Master Passphrase with N
key shares, requiring K shares)
- Key rotation for Transit
- KV versioning
- Tamper-evident audit log (hash-chained, detects log tampering)
- Opening verify() to any authenticated user, not just the key owner

## Project structure

```markdown
StudentID1_StudentID2_StudentID3/
├── README.md
├── requirements.txt
├── .env.example
├── main.py
├── src/
│ ├── core/ # Master Passphrase, init/unlock, DEK (section 0.1)
│ ├── auth/ # Register/login, session token (section 0.2)
│ ├── kv/ # Feature 1: Secure Storage
│ ├── transit/ # Feature 2: Encryption & Signing as a Service
│ └── storage/ # Read/write data to disk
├── tests/
├── data/{samples,logs}/
└── docs/report/
```

## API

| Method | Endpoint | Authentication | Input |
| --- | --- | --- | --- |
| POST | `/api/auth/register` | None | ? |
| POST | `/api/auth/login` | None | ? |
| GET | `/api/auth/me` | Bearer token | ? |
| POST | `/api/auth/logout` | Bearer token | ? |
| POST | `/api/kv/access/check` | Bearer token | json (Eg: `{"path":"secret/alice@example.com/db"}`) |
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

<!-- - **0.2 User authentication**: Argon2id password hashing, opaque 30-minute sessions, five-failure/five-minute lockout.
- **1.2 KV ownership access control**: fixed `secret/<email>/...` namespace, authorization before storage/crypto, generic cross-user denial, denied-attempt logging.
- **2.2 Transit encrypt/decrypt**: AES-256-GCM, fresh nonce per encryption, self-describing ciphertext, tamper rejection, locked-vault enforcement, and owner-scoped named-key lookup. -->

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
# Change the .env to actual value
python reinit_all.py
python main.py
```

**Note**: It is important to set venv folder to this directory. As current default config will use `.venv` location to locate the template and static folder

Open `http://127.0.0.1:5000/register`.

## Tests

```bash
pytest -q
```
<!-- 
Coverage includes:

- owner path accepted and cross-user path denied/logged;
- missing token rejected before path authorization;
- AES-GCM round trips for text, JSON, and arbitrary binary bytes;
- one-byte ciphertext tampering rejected;
- malformed/truncated ciphertext rejected;
- wrong key usage rejected;
- cross-user named-key use denied;
- locked vault rejected;
- UI authentication and rendering. -->
