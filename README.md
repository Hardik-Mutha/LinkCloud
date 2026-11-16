# ☁️ LinkCloud – Cloud-Based URL Shortener with Analytics & Security Hardening

> **A secure, production-hardened college project demonstrating URL shortening, click tracking, parameterized SQLite database queries, live analytics charts, custom aliases, QR code generation, and OWASP-aligned Flask security engineering.**

---

## 📌 Project Overview

**LinkCloud** is a modern, lightweight URL shortener that converts long URLs into compact, memorable short links while tracking visitor engagement. It features a dark navy and purple glassmorphic UI, real-time analytics, custom aliases, on-the-fly QR code generation, and robust security defenses.

Tailored for academic evaluation, cloud computing coursework, and web development demonstrations, LinkCloud separates public access (redirection and QR code generation) from administrative privileges (short link creation, custom aliases, and analytics).

---

## 🛡️ Security Architecture & Engineering Controls

LinkCloud has been hardened according to web application security best practices:

1. **Environment-Driven Secret Key**:
   - Production (`FLASK_ENV=production`) strictly requires a cryptographically secure `SECRET_KEY` of at least 32 characters set via environment variable. Default or weak fallback keys raise a `RuntimeError` at startup.
   - Development mode provides a safe local fallback key for frictionless evaluation.
2. **Strict Production Debug Mode Enforcement**:
   - `debug=True` is strictly disabled in production environments to prevent arbitrary code execution via interactive debuggers.
3. **Administrator Authentication & Hashed Credentials**:
   - Admin credentials (`ADMIN_USERNAME` and `ADMIN_PASSWORD_HASH`) are configured via environment variables.
   - Passwords are verified using cryptographic password hashing (PBKDF2/scrypt via `werkzeug.security`).
   - Session fixation is mitigated by regenerating sessions and tokens upon login.
4. **Role-Based Endpoint Protection**:
   - `/analytics` and `/api/stats` are protected behind administrator authentication; unauthenticated requests are redirected or receive `401 Unauthorized`.
   - `/shorten` requires administrator authentication for link and alias creation.
   - Public short-link redirection (`/<short_code>`) and QR codes (`/qr/<short_code>`) remain 100% accessible to public visitors without requiring login.
5. **Session Cookie Hardening**:
   - `SESSION_COOKIE_HTTPONLY = True`: Mitigates cookie theft via cross-site scripting (XSS).
   - `SESSION_COOKIE_SAMESITE = "Lax"`: Defends against cross-site request forgery.
   - `SESSION_COOKIE_SECURE = True`: Enforces transmission exclusively over HTTPS in production.
   - `PERMANENT_SESSION_LIFETIME = timedelta(hours=8)`: Limits session exposure window.
6. **Synchronizer Token CSRF Protection**:
   - Per-session cryptographically random tokens (`secrets.token_hex(32)`) protect all state-changing requests (`POST`, `PUT`, `DELETE`).
   - Validated server-side using constant-time string comparison (`hmac.compare_digest`).
   - Integrated into web forms via hidden input and AJAX fetch calls via `X-CSRF-Token` headers.
7. **Sliding-Window Rate Limiting & Request Throttling**:
   - In-memory rate limiting applied per client IP:
     - Public Redirects (`/<short_code>`): 120 requests / min.
     - Public QR Generation (`/qr/<short_code>`): 60 requests / min (mitigates CPU/image exhaustion).
     - Administrator Login (`/login`): 10 requests / min (mitigates brute-force attacks).
     - Link Creation (`/shorten`): 30 requests / min.
   - Returns `HTTP 429 Too Many Requests` with `Retry-After` headers.
8. **Request Body Size Limits**:
   - `MAX_CONTENT_LENGTH = 16 * 1024` (16 KB payload cap) prevents denial-of-service memory exhaustion, returning `HTTP 413 Payload Too Large`.
9. **Defense-in-Depth HTTP Security Headers**:
   - `X-Content-Type-Options: nosniff`: Prevents MIME-type confusion attacks.
   - `X-Frame-Options: DENY`: Blocks clickjacking attacks.
   - `Content-Security-Policy`: Restricts scripts, styles, fonts, and frame embedding to authorized origins.
   - `Referrer-Policy: strict-origin-when-cross-origin`: Minimizes referrer leakage.
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains`: Enforces HTTPS in production.
10. **Privacy & Non-Invasive Tracking**:
    - The SQLite `click_logs` table records only timestamps, referrers, and user-agent strings. IP addresses are **never stored** in the database.
    - Public APIs do not expose raw click logs or sensitive server details.
11. **Strict URL Destination Validation & Anti-SSRF**:
    - Redirect destinations are restricted strictly to `http://` and `https://`.
    - Dangerous URI schemes (`javascript:`, `data:`, `file:`, `ftp:`) are blocked.
    - Embedded credentials (`https://user:pass@evil.com`) and CRLF characters (`\r`, `\n`) are rejected.
    - Loopback recursion to self or localhost is prohibited.
    - Destination URLs are **never fetched server-side**, eliminating Server-Side Request Forgery (SSRF).
12. **Open Redirect Prevention**:
    - Post-login `next` redirection validates that target paths are strictly relative (preventing malicious redirects to external sites).

---

## ✨ Application Features

- **Lightning-Fast URL Shortening**: Converts any valid URL into a compact short link ($62^6 \approx 56.8\text{ billion}$ random code combinations).
- **Custom Short Link Aliases**: Administrators can define personalized paths (e.g. `/portfolio`, `/cloud-demo`) with collision and reserved-route checking.
- **On-The-Fly QR Codes**: Scannable, high-contrast PNG QR codes generated dynamically with download capability.
- **7-Day Click Activity Trend Chart**: Responsive line chart powered by Chart.js aggregating daily redirection traffic.
- **Live Analytics Dashboard**: Displays total links, total clicks, top performers, engagement metrics, and searchable links table.
- **Dark Glassmorphic UI**: High-contrast, responsive user experience built with modern CSS glassmorphism, ambient light orbs, and Outfit/Inter typography.

---

## 🛠️ Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.9+ & Flask 3.x | Request handling, routing, session security, and validation |
| **WSGI Server** | Gunicorn | Production WSGI HTTP server for Linux/Ubuntu |
| **Reverse Proxy** | Nginx | TLS termination, static asset serving, and reverse proxy |
| **Database** | SQLite 3 (`linkcloud.db`) | Parameterized SQL query storage for links and click counters |
| **Security & Hashing** | Werkzeug & Secrets | Password hashing, ProxyFix, and token generation |
| **QR Code Engine** | `qrcode` & `Pillow` | Scannable PNG QR code rendering |
| **Data Visualization** | Chart.js | 7-day click trend graph |
| **Frontend** | HTML5 / CSS3 / Vanilla JS | Responsive glassmorphic layout, CSRF handling, and modal dialogs |

---

## 📁 Project Structure

```text
LinkCloud/
├── app.py                # Main Flask application, security middleware, and routes
├── requirements.txt      # Python dependencies (Flask, qrcode, pillow, gunicorn, python-dotenv)
├── linkcloud.db          # SQLite database (auto-created on startup, ignored by git)
├── .env.example          # Template environment file with safe placeholders
├── .gitignore            # Git exclusion rules (.env, *.db, *.pem, *.key, caches)
├── README.md             # Project documentation and deployment guide
├── tests/                # Automated security test suite
│   └── test_security.py  # 26 automated unit & integration security tests
├── templates/            # HTML templates using Jinja2
│   ├── base.html         # Master layout, navigation, CSRF meta, and QR modal
│   ├── index.html        # Home page with shortener form and auth status banner
│   ├── login.html        # Glassmorphic administrator sign-in page
│   ├── analytics.html    # Protected analytics dashboard with 7-day chart
│   └── 404.html          # Custom error page (404, 400, 413, 429)
└── static/               # Static assets
    ├── css/
    │   └── style.css     # Glassmorphic CSS design system and auth styles
    └── js/
        └── main.js       # Asynchronous client logic, CSRF headers, and QR modal
```

---

## 🚀 How to Run Locally (Development Mode)

### 1. Navigate to Project Directory
```bash
cd /Users/wisermonk/Documents/LinkCloud
```

### 2. Activate Virtual Environment
- **macOS / Linux:**
  ```bash
  source .venv/bin/activate
  ```
- **Windows:**
  ```cmd
  .venv\Scripts\activate.bat
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Local Environment (Optional)
LinkCloud runs out-of-the-box with safe development defaults:
- **Default Username**: `admin`
- **Default Password**: `admin123`

To customize local credentials, copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 5. Start the Development Server
```bash
python3 app.py
```
> **Note on Port Conflicts**: If port 5000 is occupied by macOS AirPlay, LinkCloud automatically selects port 5001, or you can specify `PORT=5001 python3 app.py`.

### 6. Access in Browser
- **Home & Shortener**: [http://127.0.0.1:5000](http://127.0.0.1:5000)
- **Admin Login**: [http://127.0.0.1:5000/login](http://127.0.0.1:5000/login)
- **Analytics Dashboard**: [http://127.0.0.1:5000/analytics](http://127.0.0.1:5000/analytics)

---

## 🧪 Running Automated Security Tests

LinkCloud includes a comprehensive automated test suite in `tests/test_security.py` verifying all security controls:

```bash
python3 -m unittest discover tests
```
or
```bash
python3 -m unittest tests/test_security.py
```

### Test Coverage Highlights:
- **Production Key Checks**: Missing or weak `SECRET_KEY` rejection.
- **Debug Mode Prevention**: Confirms debug mode cannot be enabled in production.
- **Authentication**: Valid and invalid credential verification, rate limiting, and safe `next` redirects.
- **Authorization**: Unauthenticated access to `/analytics`, `/api/stats`, and `/shorten` blocked.
- **Public Routes**: Direct 302 redirection and QR code generation without authentication.
- **CSRF Defense**: Missing or forged tokens rejected with HTTP 400.
- **Rate Limiting**: Sliding-window throttling returning HTTP 429 and `Retry-After`.
- **Payload Limits**: Payloads over 16 KB rejected with HTTP 413.
- **Headers & SSRF**: Security headers confirmed; loopback, embedded credentials, and malicious schemes blocked.

---

## 🌐 Production Deployment Guide (Ubuntu EC2 + Gunicorn + Nginx)

Follow these step-by-step instructions to safely deploy LinkCloud to an AWS EC2 Ubuntu instance:

### Step 1: Update Server & Install System Dependencies
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv nginx sqlite3 certbot python3-certbot-nginx git
```

### Step 2: Clone or Copy Project Files
Place the project into `/var/www/linkcloud`:
```bash
sudo mkdir -p /var/www/linkcloud
sudo chown -R ubuntu:ubuntu /var/www/linkcloud
cd /var/www/linkcloud
# (Copy files or git clone here)
```

### Step 3: Set Up Python Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Production Environment Variables (`.env`)
Create `/var/www/linkcloud/.env` with strict permissions:
```bash
cp .env.example .env
chmod 600 .env
```

Generate secure secrets and update `.env`:
```bash
# 1. Generate a 32-byte hexadecimal SECRET_KEY:
python3 -c "import secrets; print(secrets.token_hex(32))"

# 2. Generate a secure PBKDF2 password hash for your chosen password:
python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YOUR_CHOSEN_PASSWORD', method='pbkdf2:sha256'))"
```

Edit `.env` (`nano .env`):
```ini
FLASK_ENV=production
FLASK_DEBUG=0
SECRET_KEY=PASTE_GENERATED_32_BYTE_HEX_KEY
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=PASTE_GENERATED_PASSWORD_HASH
SESSION_COOKIE_SECURE=1
BEHIND_PROXY=1
RATE_LIMIT_REDIRECT_PER_MIN=120
RATE_LIMIT_QR_PER_MIN=60
RATE_LIMIT_LOGIN_PER_MIN=10
RATE_LIMIT_SHORTEN_PER_MIN=30
PORT=5000
```

### Step 5: Configure Permissions for SQLite Database
Ensure the web server user (`www-data` or `ubuntu`) has read and write access to the database directory and file:
```bash
sudo chown -R www-data:www-data /var/www/linkcloud
sudo chmod 750 /var/www/linkcloud
sudo chmod 660 /var/www/linkcloud/linkcloud.db
```

### Step 6: Create Systemd Service for Gunicorn
Create `/etc/systemd/system/linkcloud.service`:
```bash
sudo nano /etc/systemd/system/linkcloud.service
```

Paste the following configuration:
```ini
[Unit]
Description=LinkCloud URL Shortener (Gunicorn WSGI)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/linkcloud
EnvironmentFile=/var/www/linkcloud/.env
ExecStart=/var/www/linkcloud/.venv/bin/gunicorn \
    --workers 3 \
    --bind 127.0.0.1:5000 \
    --access-logfile /var/log/linkcloud/access.log \
    --error-logfile /var/log/linkcloud/error.log \
    --timeout 30 \
    app:app

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Create log directory and start service:
```bash
sudo mkdir -p /var/log/linkcloud
sudo chown -R www-data:www-data /var/log/linkcloud

sudo systemctl daemon-reload
sudo systemctl enable linkcloud
sudo systemctl start linkcloud
sudo systemctl status linkcloud
```

### Step 7: Configure Nginx Reverse Proxy
Create `/etc/nginx/sites-available/linkcloud`:
```bash
sudo nano /etc/nginx/sites-available/linkcloud
```

Paste the configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com; # Or your EC2 Public DNS / Elastic IP

    client_max_body_size 1M;

    # Static file serving handled directly by Nginx for performance
    location /static/ {
        alias /var/www/linkcloud/static/;
        expires 7d;
        add_header Cache-Control "public, no-transform";
    }

    # Proxy all dynamic application traffic to Gunicorn
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 30s;
        proxy_read_timeout 30s;
    }
}
```

Enable site and restart Nginx:
```bash
sudo ln -sf /etc/nginx/sites-available/linkcloud /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

### Step 8: Enable SSL / HTTPS with Let's Encrypt Certbot
```bash
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
```
Certbot will automatically install the certificate, enable TLS, and redirect HTTP traffic to HTTPS.
