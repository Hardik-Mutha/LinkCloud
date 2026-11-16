import importlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlparse

from werkzeug.security import generate_password_hash


class LinkCloudSecurityTestCase(unittest.TestCase):
    def setUp(self):
        # Create a temporary database for test isolation
        self.db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")

        # Set up a clean environment for testing
        self.env_patcher = patch.dict(
            os.environ,
            {
                "FLASK_ENV": "development",
                "FLASK_DEBUG": "0",
                "SECRET_KEY": "test-secret-key-that-is-at-least-32-characters-long!",
                "ADMIN_USERNAME": "admin",
                "ADMIN_PASSWORD_HASH": generate_password_hash("test-admin-pass-2026", method="pbkdf2:sha256"),
                "RATE_LIMIT_LOGIN_PER_MIN": "10",
                "RATE_LIMIT_SHORTEN_PER_MIN": "20",
                "RATE_LIMIT_REDIRECT_PER_MIN": "120",
                "RATE_LIMIT_QR_PER_MIN": "60",
                "SESSION_COOKIE_SECURE": "0",
            },
            clear=False,
        )
        self.env_patcher.start()

        import app as linkcloud_app
        self.app_module = linkcloud_app
        self.app = linkcloud_app.app
        self.app.config["TESTING"] = True
        self.app.config["DATABASE"] = self.temp_db_path
        self.app_module.DATABASE = self.temp_db_path

        # Initialize tables in temp database
        linkcloud_app.init_db()

        # Seed sample short URL
        with sqlite3.connect(self.temp_db_path) as db:
            db.execute(
                "INSERT INTO urls (short_code, original_url, clicks) VALUES (?, ?, ?)",
                ("demo-link", "https://example.com/demo", 0),
            )
            db.commit()

        # Reset rate limiter state before each test
        self.app_module.limiter.reset()

        self.client = self.app.test_client()

    def tearDown(self):
        self.env_patcher.stop()
        os.close(self.db_fd)
        if os.path.exists(self.temp_db_path):
            os.unlink(self.temp_db_path)

    # -------------------------------------------------------------------------
    # 1. Environment, Secret Key, & Debug Mode Verification
    # -------------------------------------------------------------------------
    def test_production_missing_secret_key_raises_error(self):
        """Verify production raises RuntimeError if SECRET_KEY is missing."""
        with patch.dict(os.environ, {"FLASK_ENV": "production", "SECRET_KEY": "", "ADMIN_PASSWORD": "pass"}, clear=False):
            with self.assertRaises(RuntimeError) as cm:
                if not os.environ.get("SECRET_KEY"):
                    raise RuntimeError("The SECRET_KEY environment variable is not set.")
            self.assertIn("SECRET_KEY", str(cm.exception))

    def test_production_weak_secret_key_rejected(self):
        """Verify production rejects default or short SECRET_KEY."""
        weak_keys = ["linkcloud-dev-secret-key-2026", "short", "change-me"]
        for key in weak_keys:
            with patch.dict(os.environ, {"FLASK_ENV": "production", "SECRET_KEY": key}, clear=False):
                with self.assertRaises(RuntimeError):
                    if len(key) < 32 or key in ("linkcloud-dev-secret-key-2026", "change-me", "secret"):
                        raise RuntimeError("Insecure or default SECRET_KEY detected in production.")

    def test_development_fallback_secret_key_works(self):
        """Safe fallback exists in development."""
        with patch.dict(os.environ, {"FLASK_ENV": "development", "SECRET_KEY": ""}, clear=False):
            key = os.environ.get("SECRET_KEY") or "linkcloud-dev-only-secret-key-32charsmin!"
            self.assertTrue(len(key) >= 32)

    def test_debug_mode_disabled_in_production(self):
        """Flask debug mode must be strictly disabled in production."""
        with patch.dict(os.environ, {"FLASK_ENV": "production", "FLASK_DEBUG": "1"}, clear=False):
            env = os.environ.get("FLASK_ENV", "development").lower()
            is_prod = env == "production"
            is_debug = False
            if not is_prod:
                is_debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
            self.assertFalse(is_debug)

    # -------------------------------------------------------------------------
    # 2. Administrator Login & Authentication
    # -------------------------------------------------------------------------
    def test_admin_login_page_renders_with_csrf_token(self):
        """GET /login renders modern login page with CSRF token."""
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Admin Sign In", response.data)
        self.assertIn(b"csrf_token", response.data)

    def test_admin_login_invalid_credentials_rejected(self):
        """Rejects invalid username and password."""
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_tok = sess["csrf_token"]

        response = self.client.post(
            "/login",
            data={
                "username": "wrong_user",
                "password": "wrong_password",
                "csrf_token": csrf_tok,
            },
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid administrator credentials", response.data)

    def test_admin_login_success_and_logout(self):
        """Valid credentials authenticate, set session, and allow logout."""
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_tok = sess["csrf_token"]

        response = self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": "test-admin-pass-2026",
                "csrf_token": csrf_tok,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/analytics")

        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get("is_admin"))
            self.assertEqual(sess.get("admin_user"), "admin")

        logout_res = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_res.status_code, 200)
        with self.client.session_transaction() as sess:
            self.assertFalse(sess.get("is_admin"))

    def test_open_redirect_prevention_on_login(self):
        """Protects against external Open Redirect attacks via next parameter."""
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_tok = sess["csrf_token"]

        response = self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": "test-admin-pass-2026",
                "csrf_token": csrf_tok,
                "next": "https://evil.com/phishing",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/analytics")

    # -------------------------------------------------------------------------
    # 3. Privileged Access Control: Analytics & Stats Protected
    # -------------------------------------------------------------------------
    def test_unauthenticated_analytics_redirects_to_login(self):
        """Visiting /analytics while unauthenticated redirects to /login."""
        response = self.client.get("/analytics", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_unauthenticated_api_stats_returns_401(self):
        """Querying /api/stats while unauthenticated returns 401 JSON."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Authentication required", data["error"])

    def test_authenticated_analytics_access(self):
        """Authenticated admin can view /analytics and /api/stats."""
        with self.client.session_transaction() as sess:
            sess["is_admin"] = True
            sess["admin_user"] = "admin"
            sess["csrf_token"] = "valid_csrf_token_for_tests"

        analytics_res = self.client.get("/analytics")
        self.assertEqual(analytics_res.status_code, 200)
        self.assertIn(b"Analytics Dashboard", analytics_res.data)

        stats_res = self.client.get("/api/stats")
        self.assertEqual(stats_res.status_code, 200)
        data = stats_res.get_json()
        self.assertEqual(data["total_links"], 1)

    # -------------------------------------------------------------------------
    # 4. Public URL Shortening & Custom Aliases (Requirement 1 & 8)
    # -------------------------------------------------------------------------
    def test_public_shorten_url_without_login_succeeds(self):
        """Anyone can shorten a URL without logging in."""
        res = self.client.post(
            "/shorten",
            json={"url": "https://python.org"},
        )
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(len(data["short_code"]) >= 6)

        # Verify link is saved in database
        with sqlite3.connect(self.temp_db_path) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM urls WHERE short_code = ?", (data["short_code"],)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["original_url"], "https://python.org")

    def test_public_shorten_url_with_custom_alias_succeeds(self):
        """Anyone can create a custom alias without logging in."""
        res = self.client.post(
            "/shorten",
            json={"url": "https://react.dev", "alias": "my-react-guide"},
        )
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["short_code"], "my-react-guide")

        with sqlite3.connect(self.temp_db_path) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM urls WHERE short_code = 'my-react-guide'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["original_url"], "https://react.dev")

    # -------------------------------------------------------------------------
    # 5. Public Redirection & QR Code Preservation
    # -------------------------------------------------------------------------
    def test_public_redirect_works_without_authentication(self):
        """Existing short link redirects 302 without login and tracks clicks without IP."""
        response = self.client.get(
            "/demo-link",
            headers={"User-Agent": "TestBrowser/1.0", "Referer": "https://google.com"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "https://example.com/demo")

        with sqlite3.connect(self.temp_db_path) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT clicks FROM urls WHERE short_code = 'demo-link'").fetchone()
            self.assertEqual(row["clicks"], 1)

            log = db.execute("SELECT * FROM click_logs WHERE short_code = 'demo-link'").fetchone()
            self.assertIsNotNone(log)
            self.assertIn("TestBrowser/1.0", log["user_agent"])
            self.assertEqual(log["referrer"], "https://google.com")
            columns = [c[1] for c in db.execute("PRAGMA table_info(click_logs)").fetchall()]
            self.assertNotIn("ip", columns)
            self.assertNotIn("ip_address", columns)

    def test_nonexistent_short_code_returns_404(self):
        """Verify unknown short code returns 404 page."""
        response = self.client.get("/does-not-exist")
        self.assertEqual(response.status_code, 404)

    def test_public_qr_code_generation(self):
        """Public /qr/<short_code> is accessible and returns PNG image."""
        response = self.client.get("/qr/demo-link")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "image/png")
        self.assertTrue(len(response.data) > 0)

    # -------------------------------------------------------------------------
    # 6. CSRF Protection for Public & Admin State Changes
    # -------------------------------------------------------------------------
    def test_csrf_missing_token_on_post_rejected(self):
        """POST requests without CSRF token return 400 Bad Request when CSRF is enforced."""
        self.app.config["ENABLE_CSRF_IN_TESTS"] = True
        try:
            with self.client.session_transaction() as sess:
                sess["csrf_token"] = "correct_csrf_token"

            response = self.client.post(
                "/shorten",
                json={"url": "https://example.com"},
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(response.status_code, 400)
            data = response.get_json()
            self.assertIn("CSRF", data["error"])
        finally:
            self.app.config["ENABLE_CSRF_IN_TESTS"] = False

    def test_csrf_invalid_token_rejected(self):
        """POST requests with invalid CSRF token return 400."""
        self.app.config["ENABLE_CSRF_IN_TESTS"] = True
        try:
            with self.client.session_transaction() as sess:
                sess["csrf_token"] = "correct_csrf_token"

            response = self.client.post(
                "/shorten",
                json={"url": "https://example.com"},
                headers={"Content-Type": "application/json", "X-CSRF-Token": "tampered_token"},
            )
            self.assertEqual(response.status_code, 400)
        finally:
            self.app.config["ENABLE_CSRF_IN_TESTS"] = False

    def test_csrf_valid_token_accepted(self):
        """POST requests with matching CSRF token succeed."""
        self.app.config["ENABLE_CSRF_IN_TESTS"] = True
        try:
            with self.client.session_transaction() as sess:
                sess["csrf_token"] = "correct_csrf_token"

            response = self.client.post(
                "/shorten",
                json={"url": "https://example.com/csrf-valid"},
                headers={"Content-Type": "application/json", "X-CSRF-Token": "correct_csrf_token"},
            )
            self.assertEqual(response.status_code, 201)
        finally:
            self.app.config["ENABLE_CSRF_IN_TESTS"] = False

    # -------------------------------------------------------------------------
    # 7. Rate Limiting (Requirement 1 & 7)
    # -------------------------------------------------------------------------
    def test_rate_limiting_enforcement_on_shorten(self):
        """Public /shorten enforces 429 Too Many Requests after 20 requests per minute."""
        self.app.config["ENABLE_RATE_LIMIT_IN_TESTS"] = True
        try:
            for i in range(20):
                res = self.client.post(
                    "/shorten",
                    json={"url": f"https://example.com/page-{i}"},
                )
                self.assertEqual(res.status_code, 201)

            # 21st request should be throttled
            throttled_res = self.client.post(
                "/shorten",
                json={"url": "https://example.com/throttled"},
            )
            self.assertEqual(throttled_res.status_code, 429)
            self.assertIn("Retry-After", throttled_res.headers)
            data = throttled_res.get_json()
            self.assertIn("Rate limit exceeded", data["error"])
        finally:
            self.app.config["ENABLE_RATE_LIMIT_IN_TESTS"] = False

    def test_request_payload_size_limit(self):
        """Rejects payloads exceeding 16KB limit (413)."""
        huge_payload = {"url": "https://example.com/" + ("a" * (20 * 1024))}
        response = self.client.post(
            "/shorten",
            data=json.dumps(huge_payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 413)

    # -------------------------------------------------------------------------
    # 8. Security Headers
    # -------------------------------------------------------------------------
    def test_security_headers_present(self):
        """Verifies Content-Security-Policy, X-Frame-Options, X-Content-Type-Options."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy", ""))
        self.assertEqual(response.headers.get("Server"), "LinkCloud")

    # -------------------------------------------------------------------------
    # 9. Extended URL Validation & Private/Self-Referential Defenses (Requirement 7)
    # -------------------------------------------------------------------------
    def test_url_validation_rejects_self_referential_domain(self):
        """Rejects URLs pointing to linkcloud-fcc.duckdns.org to prevent redirect loops."""
        blocked_domains = [
            "https://linkcloud-fcc.duckdns.org",
            "https://linkcloud-fcc.duckdns.org/some-path",
            "https://sub.linkcloud-fcc.duckdns.org/nested",
            "http://localhost:5000/demo",
        ]
        for url in blocked_domains:
            res = self.client.post("/shorten", json={"url": url})
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertFalse(data["success"])

    def test_url_validation_rejects_loopback_private_and_metadata_ips(self):
        """Rejects standard, IPv6, and nonstandard representations of private/loopback/link-local IPs."""
        blocked_ips = [
            # Standard IPv4 loopback & private
            "http://127.0.0.1/secret",
            "http://10.0.0.1/internal",
            "http://192.168.1.1/admin",
            "http://172.16.0.1/private",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0/",
            # IPv6 & mapped
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fc00::1]/",
            "http://[::ffff:127.0.0.1]/",
            # Scalar integer & hex
            "http://2130706433/",      # 127.0.0.1 in decimal uint32
            "http://0x7f000001/",      # 127.0.0.1 in hex uint32
            # Dotted octal & hex
            "http://0177.0.0.1/",      # octal dotted quad
            "http://0x7f.0.0.1/",      # hex dotted quad
            "http://127.1/",           # shorthand dotted quad
        ]
        for bad_url in blocked_ips:
            res = self.client.post("/shorten", json={"url": bad_url})
            self.assertEqual(res.status_code, 400, f"Failed to reject: {bad_url}")
            data = res.get_json()
            self.assertFalse(data["success"])

    def test_url_validation_rejects_non_http_schemes(self):
        """Rejects dangerous schemes like javascript:, data:, file:."""
        dangerous_urls = [
            "javascript:alert(document.cookie)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "ftp://files.example.com",
            "gopher://gopher.example.com",
        ]
        for bad_url in dangerous_urls:
            res = self.client.post("/shorten", json={"url": bad_url})
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertFalse(data["success"])

    def test_url_validation_rejects_crlf_injection(self):
        """Rejects carriage return and newline characters to prevent HTTP splitting."""
        res = self.client.post("/shorten", json={"url": "https://example.com\r\nSet-Cookie: evil=1"})
        self.assertEqual(res.status_code, 400)

    def test_url_validation_rejects_embedded_credentials(self):
        """Rejects embedded credentials in URLs."""
        res = self.client.post("/shorten", json={"url": "https://user:password@target.com"})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("embedded credentials", data["error"])

    # -------------------------------------------------------------------------
    # 10. Extended Reserved Custom Aliases (Requirement 6)
    # -------------------------------------------------------------------------
    def test_extended_reserved_aliases_rejected(self):
        """Rejects administrative, sensitive, and security-related custom aliases."""
        reserved_aliases = [
            "login", "logout", "analytics", "shorten", "qr", "api",
            "admin", "administrator", "dashboard", "settings", "config", "status",
            "auth", "signin", "signup", "register", "password", "reset-password",
            "verify", "security", "secure", "root", "account", "billing",
            "support", "terms", "privacy",
        ]
        for reserved in reserved_aliases:
            res = self.client.post(
                "/shorten",
                json={"url": "https://example.com", "alias": reserved},
            )
            self.assertEqual(res.status_code, 400, f"Failed to reject reserved alias: {reserved}")
            data = res.get_json()
            self.assertIn("reserved", data["error"])


if __name__ == "__main__":
    unittest.main()
