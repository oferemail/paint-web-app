# Paint Web App

A multi-user browser paint app with:
- Email/password sign up and sign in
- Social sign-in with Google/Facebook OAuth
- Sign out
- Save and load each user's latest painting
- Export PNG download

## Security

- Passwords are hashed with `crypto.scrypt` + per-user random salt
- Sessions are stored server-side in PostgreSQL
- Session cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` on HTTPS
- SQL uses parameterized queries (no string interpolation)
- Auth failures use generic responses (no account-existence hints)
- Auth endpoints include basic rate limiting and failure delay
- Password reset tokens are random, hashed in DB, single-use, and expire in 30 minutes
- Password reset invalidates all active sessions for that account

## Database

This app requires PostgreSQL in production (for Vercel, add a Postgres integration and env var):
- `POSTGRES_URL` (or `DATABASE_URL`)

Schema is auto-created on first API request (`users` and `sessions` tables).

## Email (Password Reset)

Preferred (no SMTP needed): Resend API
- `RESEND_API_KEY`
- `RESEND_FROM` (example: `Paint App <onboarding@resend.dev>`)
- `APP_BASE_URL` (example: `https://paint-web-app-taupe.vercel.app`)

## Secret Handling

- Never commit `.env` files or raw API keys
- Store production secrets only in Vercel encrypted environment variables
- Use separate keys per environment when possible
- Rotate keys immediately after accidental exposure

## Social OAuth (Free)

Google and Facebook OAuth are free to set up (provider app registration required).
Add these environment variables:
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `FACEBOOK_APP_ID`
- `FACEBOOK_APP_SECRET`

Both providers must allow callback URLs:
- `https://paint-web-app-taupe.vercel.app/api/oauth/google/callback`
- `https://paint-web-app-taupe.vercel.app/api/oauth/facebook/callback`

## Run locally

1. Set DB env var:
   ```bash
   export DATABASE_URL='postgres://USER:PASSWORD@HOST:5432/DBNAME'
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the server:
   ```bash
   npm start
   ```
4. Open [http://localhost:3000](http://localhost:3000)
