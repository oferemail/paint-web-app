# Paint Web App

A multi-user browser paint app with:
- Email/password sign up and sign in
- Sign out
- Save and load each user's latest painting
- Export PNG download

## Run locally

1. Start the server:
   ```bash
   npm start
   ```
2. Open [http://localhost:3000](http://localhost:3000)

## Notes

- User accounts and saved paintings are stored in `db.json`.
- Passwords are hashed using Node's `crypto.scrypt`.
- Sessions are cookie-based.
