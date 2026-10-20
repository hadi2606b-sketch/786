# GB Tour Hub

A responsive Gilgit-Baltistan tourism website with a Node.js/Express backend, account signup/signin, server-side sessions, SQLite persistence, tour pricing and authenticated booking requests.

## Features

- Responsive landing page and district/tour package cards
- User registration and login with bcrypt password hashing
- Server-side session cookies; sessions stored in SQLite rather than memory
- User-specific booking history and authenticated trip requests
- Server-calculated package totals (prices are never trusted from the browser)
- Basic authentication/booking rate limits, Helmet security headers and input validation
- SQLite database created automatically on first run

## Requirements

- Node.js 20 or newer
- npm

## Run locally

```bash
npm install
cp .env.example .env
```

Set `SESSION_SECRET` in `.env` to a long, random value, then:

```bash
npm start
```

Open http://localhost:3000.

## API

- `GET /api/health` — health check
- `GET /api/tours` — tour packages and indicative PKR pricing
- `GET /api/auth/me` — current signed-in user
- `POST /api/auth/signup` — `{ "name", "email", "password" }`
- `POST /api/auth/login` — `{ "email", "password" }`
- `POST /api/auth/logout` — end the current session
- `GET /api/bookings` — current user's bookings (login required)
- `POST /api/bookings` — `{ "tourId", "travelDate", "travellers", "notes" }` (login required)

## Deployment notes

Deploy to a Node.js host such as Render, Railway or another service that supports a persistent writable disk. Set `NODE_ENV=production`, `SESSION_SECRET` to a secure random secret, and `DATA_DIR` to a persistent disk directory. HTTPS is required in production because session cookies use `Secure`. Do not deploy this backend as a static-only GitHub Pages site; GitHub Pages cannot run Express or store sessions.

The SQLite database and session store need persistent storage. Back up the data directory. For multi-instance deployments, use a managed database and shared session store instead of local SQLite.

## Tour prices

Prices displayed are **indicative starting estimates per person in PKR**, for planning only. They are not live quotes or confirmed reservations. Transport, accommodation, season, group size and local conditions change the final cost. Booking requests are saved as pending and require confirmation; this project does not collect payments or promise availability.

## Before accepting real customers

- Replace placeholder contact details with a monitored business email/phone.
- Confirm each package's inclusions, exclusions, exact itinerary and prices.
- Add verified business policies, privacy policy, cancellation/refund policy and emergency contact.
- Add email verification/password reset and payment processing only through a trusted provider.
