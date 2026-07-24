## API

| Method | Endpoint | Authentication |
|---|---|---|
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
python main.py
```

Open `http://127.0.0.1:5000/auth/register`.

## Tests

```bash
pytest -q
```