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

| Method | Endpoint | Authentication |
| --- | --- | --- |
| POST | `/api/auth/register` | None |
| POST | `/api/auth/login` | None |
| GET | `/api/auth/me` | Bearer token |
| POST | `/api/auth/logout` | Bearer token |

Example:

```bash
curl -X POST http://127.0.0.1:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","passphrase":"Correct-Horse-9!","confirm_passphrase":"Correct-Horse-9!"}'

curl -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","passphrase":"Correct-Horse-9!"}'

curl http://127.0.0.1:5000/api/auth/me \
  -H "Authorization: Bearer <session-token>"
```

## Run

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Change the .env to actual value
python main.py
```

**Note**: It is important to set venv folder to this directory. As current default config will use `.venv` location to locate the template and static folder

Open `http://127.0.0.1:5000/register`.

## Tests

```bash
pytest -q
```
