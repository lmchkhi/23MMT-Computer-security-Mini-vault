## Run

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

The server starts at `http://127.0.0.1:5000`.

## API

### Register

```bash
curl -X POST http://127.0.0.1:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","passphrase":"Correct-Horse-9!","confirm_passphrase":"Correct-Horse-9!"}'
```

### Login

```bash
curl -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","passphrase":"Correct-Horse-9!"}'
```

Use the returned token on all protected endpoints:

```bash
curl http://127.0.0.1:5000/api/auth/me \
  -H "Authorization: Bearer <session-token>"
```

### Logout

```bash
curl -X POST http://127.0.0.1:5000/api/auth/logout \
  -H "Authorization: Bearer <session-token>"
```
