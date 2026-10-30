import io
import os
import re
import secrets
import sqlite3
import string
from datetime import datetime, timedelta
from urllib.parse import urlparse

import qrcode
from flask import (
    Flask,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

# Initialize Flask application
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "linkcloud-dev-secret-key-2026")
DATABASE = os.path.join(os.path.dirname(__file__), "linkcloud.db")
SHORT_CODE_LENGTH = 6

# Reserved paths that cannot be used as custom aliases to avoid routing collisions
RESERVED_ROUTES = {
    "analytics",
    "shorten",
    "api",
    "static",
    "qr",
    "favicon.ico",
    "robots.txt",
    "health",
    "index",
}


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
        # Enable column access by name instead of index
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
    Runs automatically when the application starts.
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

    # Table 2: Detailed click logs for analytics tracking
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
    """
    Generates a cryptographically secure random alphanumeric code.
    Example: 'k7X9pQ'
    """
    characters = string.ascii_letters + string.digits
    return "".join(secrets.choice(characters) for _ in range(length))


def validate_url(url_string):
    """
    Validates the long URL:
    - Normalizes scheme (defaults to https:// if missing)
    - Verifies protocol is http or https
    - Ensures valid host/domain structure
    - Prevents self-referencing redirect loops
    Returns: (is_valid: bool, cleaned_url: str or error_message: str)
    """
    if not url_string or not isinstance(url_string, str):
        return False, "Please enter a valid URL."

    cleaned = url_string.strip()

    # Reject overly long URLs to protect database and server
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
    if parsed.scheme not in ("http", "https"):
        return False, "Invalid protocol. Only http:// and https:// URLs are allowed."

    # Validate hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: No valid domain name or host found."

    # Check for domain format (must contain at least one dot or be localhost)
    if "." not in hostname and hostname != "localhost":
        return False, "Invalid domain name. Example: https://example.com"

    # Prevent loopback recursion: cannot shorten our own server's URLs
    current_host = request.host.split(":")[0].lower()
    if hostname.lower() in (current_host, "localhost", "127.0.0.1") and parsed.path.strip("/"):
        return False, "Cannot shorten an existing LinkCloud short link."

    return True, cleaned


def validate_custom_alias(alias):
    """
    Validates an optional custom short link alias:
    - Cannot conflict with application reserved routes (/analytics, /shorten, etc.)
    - Allowed length: 3 to 30 characters
    - Allowed characters: alphanumeric, hyphens (-), and underscores (_)
    Returns: (is_valid: bool, cleaned_alias: str or error_message: str)
    """
    if not alias:
        return True, ""  # No alias requested, fallback to random short code

    cleaned = alias.strip()

    # Check reserved application endpoints first
    if cleaned.lower() in RESERVED_ROUTES:
        return (
            False,
            f"The alias '{cleaned}' is reserved by the application. Please choose a different alias.",
        )

    if len(cleaned) < 3 or len(cleaned) > 30:
        return False, "Custom alias must be between 3 and 30 characters in length."

    # Only letters, numbers, hyphens, and underscores are safe in URLs
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
    # List of date objects: from 6 days ago up to today
    date_range = [today - timedelta(days=i) for i in range(6, -1, -1)]

    # Query click_logs grouped by date (clicked_at is formatted as 'YYYY-MM-DD HH:MM:SS')
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
        label = d.strftime("%b %d")  # e.g. "Oct 24"
        count = clicks_by_date.get(d_str, 0)
        chart_labels.append(label)
        chart_data.append(count)
        total_chart_clicks += count

    return chart_labels, chart_data, total_chart_clicks


# -----------------------------------------------------------------------------
# Application Routes
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    """Renders the LinkCloud Home Page where users can shorten URLs."""
    return render_template("index.html")


@app.route("/shorten", methods=["POST"])
def shorten_url():
    """
    API and form endpoint to generate a shortened URL.
    Supports optional custom alias and random code generation.
    Accepts both JSON payloads and standard form submissions.
    """
    # Extract original URL and optional alias
    if request.is_json:
        data = request.get_json() or {}
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
        # Check if the custom alias is already taken (case-insensitive)
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
        # Check if this exact URL was already shortened previously with a random code
        existing = db.execute(
            "SELECT short_code FROM urls WHERE original_url = ? ORDER BY id DESC LIMIT 1",
            (original_url,),
        ).fetchone()

        if existing:
            short_code = existing["short_code"]
        else:
            # Generate unique code with collision retry logic
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

    # Build the full short URL based on current host address
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
def generate_qr(short_code):
    """
    Generates a high-quality PNG QR code for any shortened URL.
    The QR code encodes the complete shortened URL.
    Query param ?download=1 forces a direct file attachment download.
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

    # Generate QR Code image with clear contrast
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(full_short_url)
    qr.make(fit=True)

    # Dark navy modules on crisp white background for high scan reliability
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
def redirect_to_url(short_code):
    """
    Redirects a shortened URL to its original destination
    and increments the click counter in SQLite.
    """
    db = get_db()

    # Query the original destination
    row = db.execute(
        "SELECT id, short_code, original_url, clicks FROM urls WHERE LOWER(short_code) = LOWER(?)",
        (short_code,),
    ).fetchone()

    if not row:
        # Render friendly 404 page if short code doesn't exist
        return render_template("404.html", short_code=short_code), 404

    actual_code = row["short_code"]
    original_url = row["original_url"]

    # Increment click count and update last_accessed timestamp
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "UPDATE urls SET clicks = clicks + 1, last_accessed = ? WHERE short_code = ?",
        (now, actual_code),
    )

    # Record detailed click log
    referrer = request.referrer or "Direct / None"
    user_agent = request.headers.get("User-Agent", "Unknown")[:255]
    db.execute(
        "INSERT INTO click_logs (short_code, clicked_at, referrer, user_agent) VALUES (?, ?, ?, ?)",
        (actual_code, now, referrer, user_agent),
    )

    db.commit()

    # 302 temporary redirect to original destination
    return redirect(original_url, code=302)


@app.route("/analytics")
def analytics():
    """
    Renders the Analytics Dashboard showing:
    - Summary stat cards (total links, total clicks, top link, avg clicks)
    - 7-day daily click trends chart
    - Searchable table of all shortened links
    """
    db = get_db()

    # Summary statistics
    total_links_row = db.execute("SELECT COUNT(*) AS total_links FROM urls").fetchone()
    total_clicks_row = db.execute("SELECT COALESCE(SUM(clicks), 0) AS total_clicks FROM urls").fetchone()

    total_links = total_links_row["total_links"] if total_links_row else 0
    total_clicks = total_clicks_row["total_clicks"] if total_clicks_row else 0

    # Top performing link
    top_link = db.execute(
        "SELECT short_code, original_url, clicks FROM urls WHERE clicks > 0 ORDER BY clicks DESC LIMIT 1"
    ).fetchone()

    # All links sorted by newest first
    all_links = db.execute(
        "SELECT id, short_code, original_url, clicks, created_at, last_accessed FROM urls ORDER BY id DESC"
    ).fetchall()

    # 7-day click trend data
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
def api_stats():
    """JSON API endpoint for dashboard statistics and 7-day trends."""
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


@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page."""
    return render_template("404.html"), 404


# -----------------------------------------------------------------------------
# Application Entry Point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    import socket

    if "PORT" in os.environ:
        port = int(os.environ["PORT"])
    else:
        # Detect if port 5000 is occupied (commonly by macOS AirPlay Receiver)
        port = 5000
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
        except OSError:
            port = 5001
            print(f"\n* [LinkCloud] Port 5000 is in use (often macOS AirPlay Receiver).")
            print(f"* [LinkCloud] Automatically switching to port {port}: http://127.0.0.1:{port}\n")

    app.run(host="127.0.0.1", port=port, debug=True)
else:
    init_db()
