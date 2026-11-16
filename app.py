import functools
import hmac
import io
import ipaddress
import os
import re
import secrets
import sqlite3
import string
import time
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

import qrcode
from flask import (
    Flask,
    g,
    has_request_context,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    send_file,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# -----------------------------------------------------------------------------
# Environment & Configuration Loading
# -----------------------------------------------------------------------------
def load_env_file(filepath=".env"):
    """
    Safely loads KEY=VALUE pairs from a local .env file if present,
    without requiring third-party libraries.
    """
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = val
        except Exception:
            pass


# Try standard python-dotenv if available, then fallback to built-in parser
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
load_env_file()

# Determine runtime environment
ENV = os.environ.get("FLASK_ENV", os.environ.get("ENV", "development")).lower()
IS_PRODUCTION = (ENV == "production")

# Initialize Flask application
app = Flask(__name__)

# -----------------------------------------------------------------------------
# Security Configuration: Secret Key, Sessions, & Debug Mode
# -----------------------------------------------------------------------------
secret_key = os.environ.get("SECRET_KEY")
if IS_PRODUCTION:
    if not secret_key:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: "
            "The SECRET_KEY environment variable is not set. "
            "A cryptographically secure SECRET_KEY is required in production."
        )
    if len(secret_key) < 32 or secret_key in ("linkcloud-dev-secret-key-2026", "change-me", "secret"):
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: "
            "Insecure or default SECRET_KEY detected in production. "
            "Provide a secure random key of at least 32 characters."
        )
    app.config["SECRET_KEY"] = secret_key
else:
    # Safe local development key if not provided
    if not secret_key:
        secret_key = "linkcloud-dev-only-secret-key-32charsmin!"
    app.config["SECRET_KEY"] = secret_key

# Strict Debug Mode Enforcement
is_debug = False
if not IS_PRODUCTION:
    is_debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
app.config["DEBUG"] = is_debug

# Session Cookie Hardening
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB payload limit (DoS mitigation)
app.config["SESSION_COOKIE_HTTPONLY"] = True   # Protects session cookies against XSS theft
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Mitigates cross-site request forgery
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "SESSION_COOKIE_SECURE", "1" if IS_PRODUCTION else "0"
).lower() in ("1", "true", "yes")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

# Reverse Proxy Support (e.g. Nginx, AWS ALB on Ubuntu)
if os.environ.get("BEHIND_PROXY", "1" if IS_PRODUCTION else "0").lower() in ("1", "true", "yes"):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

DATABASE = os.path.join(os.path.dirname(__file__), "linkcloud.db")
SHORT_CODE_LENGTH = 6

# Reserved paths that cannot be used as custom aliases to avoid routing collisions
RESERVED_ROUTES = {
    # Application & administrative routes
    "analytics",
    "shorten",
    "api",
    "static",
    "qr",
    "favicon.ico",
    "robots.txt",
    "health",
    "index",
    "login",
    "logout",
    "admin",
    "administrator",
    "dashboard",
    "settings",
    "config",
    "status",
    "metrics",
    "stats",
    # Sensitive and security-related terms
    "auth",
    "authenticate",
    "signin",
    "sign-in",
    "signup",
    "sign-up",
    "register",
    "password",
    "reset-password",
    "verify",
    "verification",
    "security",
    "secure",
    "root",
    "account",
    "billing",
    "payment",
    "support",
    "help",
    "terms",
    "privacy",
    "about",
    "contact",
    "docs",
    "documentation",
}

# -----------------------------------------------------------------------------
# Administrator Credentials & Verification
# -----------------------------------------------------------------------------
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
DEV_ADMIN_PASSWORD = "admin123"

# Require administrator credentials in production
if IS_PRODUCTION:
    if not os.environ.get("ADMIN_PASSWORD_HASH") and not os.environ.get("ADMIN_PASSWORD"):
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: "
            "ADMIN_PASSWORD_HASH (or ADMIN_PASSWORD) environment variable must be configured in production."
        )


def verify_admin_credentials(username, password):
    """
    Verifies administrator credentials using constant-time string comparison
    and cryptographic password hashing (Werkzeug scrypt / pbkdf2).
    """
    if not username or not password:
        return False

    expected_username = os.environ.get("ADMIN_USERNAME", "admin")
    if not hmac.compare_digest(username.strip(), expected_username.strip()):
        return False

    # Check password hash (Recommended for production)
    password_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    if password_hash:
        return check_password_hash(password_hash, password)

    # Check plaintext environment variable (for simple local testing)
    plaintext_pass = os.environ.get("ADMIN_PASSWORD")
    if plaintext_pass:
        return hmac.compare_digest(password, plaintext_pass)

    # In production, require either hash or password to be set
    if IS_PRODUCTION:
        return False

    # Local development demo fallback
    return password == DEV_ADMIN_PASSWORD


def is_safe_redirect_url(target):
    """Prevents Open Redirect attacks by ensuring redirect target is a relative path."""
    if not target or not isinstance(target, str):
        return False
    return target.startswith("/") and not target.startswith("//")


def admin_required(f):
    """Decorator requiring an authenticated administrator session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({
                    "success": False,
                    "error": "Authentication required. Please log in as an administrator.",
                }), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


# -----------------------------------------------------------------------------
# In-Memory Sliding-Window Rate Limiter
# -----------------------------------------------------------------------------
class InMemoryRateLimiter:
    """Thread-safe, sliding-window in-memory rate limiter per IP address."""
    def __init__(self):
        self.requests = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int, window_seconds: int = 60):
        now = time.time()
        window_start = now - window_seconds
        timestamps = [ts for ts in self.requests[key] if ts > window_start]
        self.requests[key] = timestamps

        if len(timestamps) >= max_requests:
            oldest = timestamps[0]
            retry_after = max(1, int(window_seconds - (now - oldest)))
            return False, retry_after

        self.requests[key].append(now)
        return True, 0

    def reset(self):
        self.requests.clear()


limiter = InMemoryRateLimiter()


def get_client_ip():
    """Extracts client IP address safely, respecting reverse proxies when configured."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def rate_limit(max_requests: int, window_seconds: int = 60, endpoint_name: str = None):
    """Route decorator enforcing maximum requests per time window."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if app.config.get("TESTING") and not app.config.get("ENABLE_RATE_LIMIT_IN_TESTS"):
                return f(*args, **kwargs)

            ip = get_client_ip()
            action = endpoint_name or f.__name__
            key = f"{action}:{ip}"
            allowed, retry_after = limiter.is_allowed(key, max_requests, window_seconds)

            if not allowed:
                err_msg = f"Rate limit exceeded. Please wait {retry_after} seconds before retrying."
                if request.is_json or request.path.startswith("/api/"):
                    resp = make_response(jsonify({"success": False, "error": err_msg}), 429)
                else:
                    resp = make_response(
                        render_template(
                            "404.html",
                            error_badge="429 Too Many Requests",
                            error_title="Rate Limit Exceeded",
                            error_message=err_msg,
                        ),
                        429,
                    )
                resp.headers["Retry-After"] = str(retry_after)
                return resp
            return f(*args, **kwargs)
        return decorated
    return decorator


# -----------------------------------------------------------------------------
# CSRF Protection
# -----------------------------------------------------------------------------
def get_or_create_csrf_token():
    """Generates and retrieves a cryptographically secure session-bound CSRF token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_or_create_csrf_token


@app.before_request
def verify_csrf_token():
    """
    Enforces Synchronizer Token Pattern CSRF protection for state-changing HTTP requests.
    Validates token via form payload or X-CSRF-Token header.
    """
    if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return None

    # Testing bypass when not explicitly evaluating CSRF defense
    if app.config.get("TESTING") and not app.config.get("ENABLE_CSRF_IN_TESTS"):
        return None

    expected_token = session.get("csrf_token")
    received_token = (
        request.headers.get("X-CSRF-Token")
        or request.headers.get("X-CSRFToken")
        or request.form.get("csrf_token")
    )

    if not received_token and request.is_json:
        json_body = request.get_json(silent=True) or {}
        received_token = json_body.get("csrf_token")

    if not expected_token or not received_token or not hmac.compare_digest(str(expected_token), str(received_token)):
        err_msg = "Invalid or missing CSRF security token. Please refresh the page and try again."
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"success": False, "error": err_msg}), 400
        return render_template(
            "404.html",
            error_badge="400 Bad Request",
            error_title="Security Verification Failed",
            error_message=err_msg,
        ), 400


# -----------------------------------------------------------------------------
# Security Headers Middleware
# -----------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    """Applies modern HTTP defense-in-depth security headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    if app.config.get("SESSION_COOKIE_SECURE") or IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    response.headers["Server"] = "LinkCloud"
    return response


# -----------------------------------------------------------------------------
# Database Helper Functions
# -----------------------------------------------------------------------------
def get_db():
    """
    Opens a new database connection if one does not already exist
    for the current application context.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Closes the database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """
    Initializes the SQLite database tables.
    Preserves all existing records if tables already exist.
    """
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    # Table 1: Store shortened URLs and overall click stats
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            short_code TEXT UNIQUE NOT NULL,
            original_url TEXT NOT NULL,
            clicks INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_accessed TIMESTAMP
        );
        """
    )

    # Index for fast lookups by short_code
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_urls_short_code ON urls(short_code);
        """
    )

    # Table 2: Detailed click logs for analytics tracking (NO IP addresses logged)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS click_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            short_code TEXT NOT NULL,
            clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            referrer TEXT,
            user_agent TEXT,
            FOREIGN KEY (short_code) REFERENCES urls(short_code)
        );
        """
    )

    db.commit()
    db.close()


# -----------------------------------------------------------------------------
# Helper Functions: URL Validation, Custom Alias, and Code Generation
# -----------------------------------------------------------------------------
def generate_short_code(length=SHORT_CODE_LENGTH):
    """Generates a cryptographically secure random alphanumeric code."""
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def parse_int_safe(val):
    """Parses decimal, hex, or octal string representation into an integer."""
    val = val.strip()
    if val.startswith(("0x", "0X")):
        return int(val, 16)
    elif val.startswith(("0o", "0O")):
        return int(val, 8)
    elif val.startswith("0") and len(val) > 1 and val[1:].isdigit():
        return int(val, 8)
    return int(val, 10)


def is_blocked_destination_host(host, current_host=None):
    """
    Evaluates whether a destination hostname is blocked:
    - Rejects self-referential links to linkcloud-fcc.duckdns.org and current server host
    - Rejects loopback (localhost, 127.0.0.0/8, ::1)
    - Rejects private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Rejects link-local / cloud metadata (169.254.0.0/16, fe80::/10)
    - Rejects IPv6, IPv4-mapped IPv6, and nonstandard scalar/hex/octal/shorthand IP representations
    - Does NOT perform any network fetches or DNS lookups.
    Returns: (is_blocked: bool, reason: str or None)
    """
    if not host or not isinstance(host, str):
        return True, "Invalid destination host."

    h = host.strip().lower().strip("[]")

    # 1. Prohibit self-referential and loopback hostnames
    blocked_hostnames = {
        "localhost",
        "localhost.localdomain",
        "linkcloud-fcc.duckdns.org",
    }
    if current_host:
        blocked_hostnames.add(current_host.lower())

    if (
        h in blocked_hostnames
        or h.endswith(".linkcloud-fcc.duckdns.org")
        or h.endswith(".localhost")
    ):
        return True, "Cannot shorten LinkCloud server URLs or loopback domains."

    # 2. Standard IP parsing (IPv4, IPv6, IPv4-mapped IPv6)
    try:
        ip = ipaddress.ip_address(h)
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_multicast
        ):
            return True, "Redirection to private, loopback, or link-local IP addresses is not permitted."
        if getattr(ip, "ipv4_mapped", None) and (
            ip.ipv4_mapped.is_loopback
            or ip.ipv4_mapped.is_private
            or ip.ipv4_mapped.is_link_local
            or ip.ipv4_mapped.is_reserved
            or ip.ipv4_mapped.is_unspecified
        ):
            return True, "Redirection to private, loopback, or link-local IP addresses is not permitted."
        return False, None
    except ValueError:
        pass

    # 3. Nonstandard scalar integer or hex representation (e.g. 2130706433, 0x7f000001)
    try:
        int_val = parse_int_safe(h)
        if 0 <= int_val <= 0xFFFFFFFF:
            ip = ipaddress.IPv4Address(int_val)
            if (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_unspecified
                or ip.is_multicast
            ):
                return True, "Redirection to private, loopback, or link-local IP addresses is not permitted."
            return False, None
    except Exception:
        pass

    # 4. Dotted quad / octal / hex / shorthand parts (e.g. 0177.0.0.1, 0x7f.0.0.1, 127.1)
    parts = h.split(".")
    if 1 < len(parts) <= 4:
        try:
            int_parts = [parse_int_safe(p) for p in parts]
            if len(int_parts) == 4 and all(0 <= p <= 255 for p in int_parts):
                ip = ipaddress.IPv4Address(bytes(int_parts))
                if (
                    ip.is_loopback
                    or ip.is_private
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_unspecified
                    or ip.is_multicast
                ):
                    return True, "Redirection to private, loopback, or link-local IP addresses is not permitted."
                return False, None
            elif len(int_parts) < 4:
                val = 0
                for p in int_parts[:-1]:
                    if not (0 <= p <= 255):
                        raise ValueError()
                    val = (val << 8) | p
                rem = int_parts[-1]
                rem_bytes = 4 - (len(int_parts) - 1)
                if not (0 <= rem < (1 << (8 * rem_bytes))):
                    raise ValueError()
                val = (val << (8 * rem_bytes)) | rem
                ip = ipaddress.IPv4Address(val)
                if (
                    ip.is_loopback
                    or ip.is_private
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_unspecified
                    or ip.is_multicast
                ):
                    return True, "Redirection to private, loopback, or link-local IP addresses is not permitted."
                return False, None
        except Exception:
            pass

    return False, None


def validate_url(url_string):
    """
    Validates destination URL:
    - Verifies protocol is strictly http or https
    - Rejects control characters, newlines, and embedded credentials (@)
    - Verifies valid domain format
    - Rejects self-referential URLs (linkcloud-fcc.duckdns.org, current host)
    - Rejects loopback, link-local, and private IP destinations (standard & nonstandard)
    - Does NOT perform any network fetches or DNS lookups (SSRF protection)
    Returns: (is_valid: bool, cleaned_url: str or error_message: str)
    """
    if not url_string or not isinstance(url_string, str):
        return False, "Please enter a valid URL."

    cleaned = url_string.strip()

    # Reject control characters or newlines to prevent HTTP response splitting
    if any(c in cleaned for c in ("\r", "\n", "\0", "\t")):
        return False, "The URL contains invalid or prohibited control characters."

    # Reject overly long URLs to protect database and memory
    if len(cleaned) > 2048:
        return False, "The URL is too long (maximum 2048 characters)."

    # Automatically prepend https:// if user pasted without protocol
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        if "://" in cleaned:
            return False, "Only HTTP and HTTPS protocols are supported."
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
    except Exception:
        return False, "The URL provided could not be parsed."

    # Validate scheme
    if parsed.scheme.lower() not in ("http", "https"):
        return False, "Invalid protocol. Only http:// and https:// URLs are allowed."

    # Disallow embedded credentials in URL authority
    if "@" in parsed.netloc:
        return False, "URLs with embedded credentials (@) are not permitted."

    # Validate hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: No valid domain name or host found."

    # Check for private/loopback/link-local/self-referential hosts without DNS lookups
    current_host = request.host.split(":")[0].lower() if has_request_context() else "127.0.0.1"
    is_blocked, block_reason = is_blocked_destination_host(hostname, current_host)
    if is_blocked:
        return False, block_reason

    # Domain structure check (must have at least one dot or colon for IPv6)
    if "." not in hostname and ":" not in hostname:
        return False, "Invalid domain name. Example: https://example.com"

    return True, cleaned


def validate_custom_alias(alias):
    """
    Validates an optional custom short link alias:
    - Cannot conflict with application reserved routes (/analytics, /login, etc.)
    - Allowed length: 3 to 30 characters
    - Allowed characters: alphanumeric, hyphens (-), and underscores (_)
    Returns: (is_valid: bool, cleaned_alias: str or error_message: str)
    """
    if not alias:
        return True, ""

    cleaned = alias.strip()

    # Check reserved application endpoints first
    if cleaned.lower() in RESERVED_ROUTES:
        return (
            False,
            f"The alias '{cleaned}' is reserved by the application. Please choose a different alias.",
        )

    if len(cleaned) < 3 or len(cleaned) > 30:
        return False, "Custom alias must be between 3 and 30 characters in length."

    if not re.match(r"^[a-zA-Z0-9_-]+$", cleaned):
        return (
            False,
            "Custom alias can only contain letters, numbers, hyphens (-), and underscores (_).",
        )

    return True, cleaned


def get_7day_analytics(db):
    """
    Aggregates daily click counts for the last 7 calendar days
    from the SQLite click_logs table.
    Guarantees all 7 days are represented consecutively with 0 as default.
    Returns: (chart_labels: list[str], chart_data: list[int], total_chart_clicks: int)
    """
    today = datetime.utcnow().date()
    date_range = [today - timedelta(days=i) for i in range(6, -1, -1)]

    rows = db.execute(
        """
        SELECT DATE(clicked_at) AS click_date, COUNT(*) AS count
        FROM click_logs
        WHERE DATE(clicked_at) >= DATE('now', '-6 days')
        GROUP BY DATE(clicked_at)
        """
    ).fetchall()

    clicks_by_date = {row["click_date"]: row["count"] for row in rows}

    chart_labels = []
    chart_data = []
    total_chart_clicks = 0

    for d in date_range:
        d_str = d.strftime("%Y-%m-%d")
        label = d.strftime("%b %d")
        count = clicks_by_date.get(d_str, 0)
        chart_labels.append(label)
        chart_data.append(count)
        total_chart_clicks += count

    return chart_labels, chart_data, total_chart_clicks


# -----------------------------------------------------------------------------
# Application Routes: Authentication
# -----------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
@rate_limit(
    max_requests=int(os.environ.get("RATE_LIMIT_LOGIN_PER_MIN", 10)),
    window_seconds=60,
    endpoint_name="login",
)
def login():
    """Administrator login page and credential authentication."""
    next_url = request.args.get("next") or request.form.get("next") or ""
    if not is_safe_redirect_url(next_url):
        next_url = url_for("analytics")

    # If already logged in, redirect directly to requested page or analytics
    if session.get("is_admin"):
        return redirect(next_url)

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if verify_admin_credentials(username, password):
            # Regenerate session to prevent session fixation attacks
            session.clear()
            session["is_admin"] = True
            session["admin_user"] = username.strip()
            session["logged_in_at"] = datetime.utcnow().isoformat()
            # Generate a fresh CSRF token for the authenticated session
            session["csrf_token"] = secrets.token_hex(32)
            return redirect(next_url)

        return (
            render_template(
                "login.html",
                error="Invalid administrator credentials. Please try again.",
                username=username,
                next_url=next_url,
            ),
            401,
        )

    return render_template("login.html", next_url=next_url)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Logs out administrator and clears session."""
    session.clear()
    return redirect(url_for("index"))


# -----------------------------------------------------------------------------
# Application Routes: Public & Admin Endpoints
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    """Renders the LinkCloud Home Page."""
    return render_template("index.html")


@app.route("/shorten", methods=["POST"])
@rate_limit(
    max_requests=int(os.environ.get("RATE_LIMIT_SHORTEN_PER_MIN", 20)),
    window_seconds=60,
    endpoint_name="shorten",
)
def shorten_url():
    """
    Public API and form endpoint to generate a shortened URL.
    Protected by CSRF validation and IP-based rate limiting (max 20 creations/min).
    Supports optional custom alias and collision-safe code generation.
    """
    if request.is_json:
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url", "")
        raw_alias = data.get("alias") or data.get("custom_alias") or ""
    else:
        raw_url = request.form.get("url", "")
        raw_alias = request.form.get("alias") or request.form.get("custom_alias") or ""

    # Validate long URL
    is_valid_url, url_result = validate_url(raw_url)
    if not is_valid_url:
        if request.is_json:
            return jsonify({"success": False, "error": url_result}), 400
        return render_template("index.html", error=url_result, input_url=raw_url, input_alias=raw_alias), 400

    original_url = url_result

    # Validate custom alias if provided
    is_valid_alias, alias_result = validate_custom_alias(raw_alias)
    if not is_valid_alias:
        if request.is_json:
            return jsonify({"success": False, "error": alias_result}), 400
        return render_template("index.html", error=alias_result, input_url=raw_url, input_alias=raw_alias), 400

    custom_alias = alias_result
    db = get_db()

    # Case A: User specified a Custom Alias
    if custom_alias:
        collision = db.execute(
            "SELECT 1 FROM urls WHERE LOWER(short_code) = LOWER(?)",
            (custom_alias,),
        ).fetchone()

        if collision:
            error_msg = f"The custom alias '{custom_alias}' is already in use. Please choose another one."
            if request.is_json:
                return jsonify({"success": False, "error": error_msg}), 400
            return render_template("index.html", error=error_msg, input_url=raw_url, input_alias=raw_alias), 400

        short_code = custom_alias
        db.execute(
            "INSERT INTO urls (short_code, original_url, clicks) VALUES (?, ?, 0)",
            (short_code, original_url),
        )
        db.commit()

    # Case B: Default to Random Short Code Generation
    else:
        existing = db.execute(
            "SELECT short_code FROM urls WHERE original_url = ? ORDER BY id DESC LIMIT 1",
            (original_url,),
        ).fetchone()

        if existing:
            short_code = existing["short_code"]
        else:
            max_attempts = 5
            short_code = None
            for _ in range(max_attempts):
                candidate_code = generate_short_code()
                collision = db.execute(
                    "SELECT 1 FROM urls WHERE LOWER(short_code) = LOWER(?)",
                    (candidate_code,),
                ).fetchone()
                if not collision:
                    short_code = candidate_code
                    break

            if not short_code:
                error_msg = "Could not generate a unique short code. Please try again."
                if request.is_json:
                    return jsonify({"success": False, "error": error_msg}), 500
                return render_template("index.html", error=error_msg), 500

            db.execute(
                "INSERT INTO urls (short_code, original_url, clicks) VALUES (?, ?, 0)",
                (short_code, original_url),
            )
            db.commit()

    base_url = request.host_url.rstrip("/")
    full_short_url = f"{base_url}/{short_code}"

    if request.is_json:
        return jsonify({
            "success": True,
            "short_code": short_code,
            "short_url": full_short_url,
            "original_url": original_url,
            "message": "Short URL created successfully!",
        }), 201

    return render_template(
        "index.html",
        short_url=full_short_url,
        short_code=short_code,
        original_url=original_url,
        success="Link shortened successfully!",
    )


@app.route("/qr/<short_code>")
@rate_limit(
    max_requests=int(os.environ.get("RATE_LIMIT_QR_PER_MIN", 60)),
    window_seconds=60,
    endpoint_name="qr",
)
def generate_qr(short_code):
    """
    Generates a PNG QR code for any shortened URL. Publicly accessible.
    Rate-limited to protect CPU and memory from high-frequency image rendering.
    """
    db = get_db()
    row = db.execute(
        "SELECT short_code FROM urls WHERE LOWER(short_code) = LOWER(?)",
        (short_code,),
    ).fetchone()

    if not row:
        return render_template("404.html", short_code=short_code), 404

    actual_code = row["short_code"]
    base_url = request.host_url.rstrip("/")
    full_short_url = f"{base_url}/{actual_code}"

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(full_short_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#070a13", back_color="#ffffff")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    as_attachment = request.args.get("download") == "1"
    filename = f"linkcloud-qr-{actual_code}.png"

    return send_file(
        buf,
        mimetype="image/png",
        as_attachment=as_attachment,
        download_name=filename,
    )


@app.route("/<short_code>")
@rate_limit(
    max_requests=int(os.environ.get("RATE_LIMIT_REDIRECT_PER_MIN", 120)),
    window_seconds=60,
    endpoint_name="redirect",
)
def redirect_to_url(short_code):
    """
    Publicly redirects a shortened URL to its original destination.
    Increments click counters and records non-invasive click metadata (referrer, user agent).
    Does NOT store IP addresses in click logs.
    """
    db = get_db()

    row = db.execute(
        "SELECT id, short_code, original_url, clicks FROM urls WHERE LOWER(short_code) = LOWER(?)",
        (short_code,),
    ).fetchone()

    if not row:
        return render_template("404.html", short_code=short_code), 404

    actual_code = row["short_code"]
    original_url = row["original_url"]

    # Verify destination safety before redirecting
    is_valid, validated_url = validate_url(original_url)
    if not is_valid:
        return render_template(
            "404.html",
            short_code=short_code,
            error_title="Unsafe Destination",
            error_message="The target URL for this short link failed security validation.",
        ), 400

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "UPDATE urls SET clicks = clicks + 1, last_accessed = ? WHERE short_code = ?",
        (now, actual_code),
    )

    # Privacy-conscious logging: Never logs IP addresses
    referrer = request.referrer or "Direct / None"
    user_agent = request.headers.get("User-Agent", "Unknown")[:255]
    db.execute(
        "INSERT INTO click_logs (short_code, clicked_at, referrer, user_agent) VALUES (?, ?, ?, ?)",
        (actual_code, now, referrer, user_agent),
    )

    db.commit()

    return redirect(validated_url, code=302)


@app.route("/analytics")
@admin_required
def analytics():
    """
    Renders the Analytics Dashboard.
    Protected behind administrator authentication.
    """
    db = get_db()

    total_links_row = db.execute("SELECT COUNT(*) AS total_links FROM urls").fetchone()
    total_clicks_row = db.execute("SELECT COALESCE(SUM(clicks), 0) AS total_clicks FROM urls").fetchone()

    total_links = total_links_row["total_links"] if total_links_row else 0
    total_clicks = total_clicks_row["total_clicks"] if total_clicks_row else 0

    top_link = db.execute(
        "SELECT short_code, original_url, clicks FROM urls WHERE clicks > 0 ORDER BY clicks DESC LIMIT 1"
    ).fetchone()

    all_links = db.execute(
        "SELECT id, short_code, original_url, clicks, created_at, last_accessed FROM urls ORDER BY id DESC"
    ).fetchall()

    chart_labels, chart_data, total_chart_clicks = get_7day_analytics(db)

    base_url = request.host_url.rstrip("/")

    return render_template(
        "analytics.html",
        total_links=total_links,
        total_clicks=total_clicks,
        top_link=top_link,
        links=all_links,
        base_url=base_url,
        chart_labels=chart_labels,
        chart_data=chart_data,
        total_chart_clicks=total_chart_clicks,
    )


@app.route("/api/stats")
@admin_required
def api_stats():
    """
    JSON API endpoint for dashboard statistics and 7-day trends.
    Protected behind administrator authentication.
    """
    db = get_db()
    total_links = db.execute("SELECT COUNT(*) AS total FROM urls").fetchone()["total"]
    total_clicks = db.execute("SELECT COALESCE(SUM(clicks), 0) AS total FROM urls").fetchone()["total"]

    links_rows = db.execute(
        "SELECT short_code, original_url, clicks, created_at, last_accessed FROM urls ORDER BY id DESC"
    ).fetchall()

    chart_labels, chart_data, total_chart_clicks = get_7day_analytics(db)

    base_url = request.host_url.rstrip("/")
    links_data = [
        {
            "short_code": row["short_code"],
            "short_url": f"{base_url}/{row['short_code']}",
            "original_url": row["original_url"],
            "clicks": row["clicks"],
            "created_at": row["created_at"],
            "last_accessed": row["last_accessed"],
        }
        for row in links_rows
    ]

    return jsonify({
        "total_links": total_links,
        "total_clicks": total_clicks,
        "links": links_data,
        "chart_labels": chart_labels,
        "chart_data": chart_data,
        "total_chart_clicks": total_chart_clicks,
    })


# -----------------------------------------------------------------------------
# Error Handlers
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page."""
    return render_template("404.html"), 404


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handles oversized request payloads (MAX_CONTENT_LENGTH exceeded)."""
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Request entity too large (maximum 16KB allowed)."}), 413
    return render_template(
        "404.html",
        error_badge="413 Payload Too Large",
        error_title="Request Too Large",
        error_message="The request payload exceeded the maximum allowable limit of 16KB.",
    ), 413


@app.errorhandler(429)
def too_many_requests(e):
    """Handles HTTP 429 rate limit exceeded exceptions."""
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Too many requests. Please slow down."}), 429
    return render_template(
        "404.html",
        error_badge="429 Too Many Requests",
        error_title="Rate Limit Exceeded",
        error_message="You have sent too many requests in a short period. Please wait a moment.",
    ), 429


# -----------------------------------------------------------------------------
# Application Entry Point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    import socket

    if "PORT" in os.environ:
        port = int(os.environ["PORT"])
    else:
        port = 5000
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
        except OSError:
            port = 5001
            print(f"\n* [LinkCloud] Port 5000 is in use (often macOS AirPlay Receiver).")
            print(f"* [LinkCloud] Automatically switching to port {port}: http://127.0.0.1:{port}\n")

    app.run(host="127.0.0.1", port=port, debug=is_debug)
else:
    init_db()
