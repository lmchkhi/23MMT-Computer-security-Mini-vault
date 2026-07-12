# Computer security project 1 - Mini vault

## Description

A project about creating a mini vault for storing application secretes

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
