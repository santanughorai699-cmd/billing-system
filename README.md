# Kalyani Embroidery Bill Management System

A bill-management web app with a React-based frontend, an Express backend (`server.js`), and an alternate FastAPI backend (`index.py`). Both backends serve `index.html` and use SQLite by default; they can use PostgreSQL when `DATABASE_URL` is configured.

## Requirements

- Node.js 18 or newer and npm to run the Express backend
- Python 3.8 or newer to run the FastAPI backend

## Run with Node.js (recommended)

From the project directory, install dependencies and start the server:

```powershell
npm install
npm start
```

Open [http://localhost:8000](http://localhost:8000). To use Node's watch mode during development, run `npm run dev`.

The server uses port `8000` by default. Set the `PORT` environment variable to use a different port.

## Run with Python (alternative)

Install the Python dependencies and start FastAPI:

```powershell
python -m pip install -r requirements.txt
python index.py
```

Open [http://localhost:8000](http://localhost:8000). The app's API documentation is disabled by default.

Run only one backend at a time unless you configure different ports and database settings.

## Initial accounts

On first startup, if the database has no users, the app creates these accounts:

| Role | User ID | Default password |
| --- | --- | --- |
| Admin | `samaresh` | `s1` |
| Employee | `bimal` | `b2` |
| Employee | `susama` | `s3` |

User IDs are case-insensitive. These defaults are only used when the `users` table is empty; starting the app again does not reset existing passwords. Set `ADMIN_DEFAULT_PASS`, `EMP1_DEFAULT_PASS`, and `EMP2_DEFAULT_PASS` before the first startup to choose initial passwords. Change default credentials before exposing the app to a network.

## Data and database

SQLite is used unless `DATABASE_URL` starts with `postgres`. With SQLite, the database file `billing_system.db` is created in the directory where the server is started. Bills, users, and sessions are stored there and persist across restarts.

To use PostgreSQL, set `DATABASE_URL` to your PostgreSQL connection URL. The Node backend includes the `pg` package. The Python backend also requires `psycopg2-binary`, which is listed in `requirements.txt`.

Back up the database regularly. **Deleting `billing_system.db` permanently removes the locally stored bills and accounts**; the app will create a new database and seed the initial accounts on its next startup.

## Features and access

- Create, view, and edit bills; pending balances are calculated from the amount and advance.
- Bill creation dates are recorded automatically and displayed as `DD-MM-YY`. Enter delivery dates as `DD-MM-YY`; impossible dates and other formats are rejected. Two-digit years are interpreted as 2000-2099.
- Track who created each bill and which worker completed its garment work. Any user can request a completed-work attribution change; the current worker or an admin must approve it before the requested worker is assigned, while admins can also update it directly. Admins can view completed-job counts grouped by worker and completion day.
- View recent work completion, reassignment, change requests, approvals, and rejections in the shared notification menu at the top of the dashboard.
- Set delivery dates and receive a shared dashboard reminder starting three days before delivery; any authenticated user can accept it, reject it for the current session, or schedule it for another date.
- Expand the garment-measurement section while entering a bill to save measurements (ঝুল, ছাতি, কোমর, পুট, হাতা, মহরী, মহড়া, পে, কছ); enter values such as `14` directly and tap the `1/2` button to add `½`. Open saved measurements from the customer name or the bill's measurement button.
- All authenticated users can view and edit all bills.
- Only admins can delete bills and manage users.
- Admins can add employees with a name, phone number, and password; the app generates a unique login ID from the name and displays it after creation. Admins can also change roles, reset passwords, and delete users.
- Phone numbers are entered as 10-digit Indian mobile numbers; the country code `91` is added for storage and WhatsApp links.
- Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes, not as plaintext.
- Sessions expire after 24 hours.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `PORT` | Express server port | `8000` |
| `DATABASE_URL` | PostgreSQL connection URL; SQLite is used otherwise | unset |
| `ADMIN_DEFAULT_PASS` | Initial admin password when creating seed users | `s1` |
| `EMP1_DEFAULT_PASS` | Initial password for `bimal` when creating seed users | `b2` |
| `EMP2_DEFAULT_PASS` | Initial password for `susama` when creating seed users | `s3` |
| `ALLOWED_ORIGINS` | Comma-separated allowed browser origins | `http://localhost:8000,http://127.0.0.1:8000,null` |
| `ALLOWED_HOSTS` | Comma-separated allowed hostnames | `*` |

For the Python backend, set `ENV=development` to enable Uvicorn reload. Do not expose a development server directly to the public internet.

## Troubleshooting

### The page reports that the backend is unreachable

Confirm that one backend is running, then reload the page. Check the server console for startup or database errors.

### Port 8000 is already in use

Stop the other process using the port or set a different `PORT` for the Express backend. The Python entry point currently uses port `8000`.

### A default login does not work

Seed accounts are created only when the `users` table is empty. Existing accounts and passwords are preserved on restart. Ask an administrator to reset the password, or check whether the database is the expected one.

### Login is locked out after repeated attempts

The firewall rate-limits login attempts. Wait five minutes before trying again.
