# ☁️ LinkCloud – Cloud-Based URL Shortener with Analytics

> **A beginner-friendly college project demonstrating URL shortening, click tracking, secure database queries, live analytics charts, custom aliases, and QR code generation using Python Flask, SQLite, and modern web technologies.**

---

## 📌 Project Overview

**LinkCloud** is a lightweight, responsive web application that turns long URLs into compact, memorable short links while tracking visitor engagement. It features a dark navy and purple glassmorphic UI, real-time analytics, custom aliases, QR code generation, and safe database practices.

This project is tailored for academic evaluation, cloud computing coursework, and web development demonstrations.

---

## ✨ Features

1. **URL Shortening**: Paste any valid URL and generate an instantaneous short link tied to your local Flask server.
2. **Safe URL Validation**: Validates URL structure, auto-prefixes `https://` if protocol is omitted, enforces HTTP/HTTPS only, and prevents recursive redirect loops.
3. **Cryptographically Secure Short Codes**: Uses Python's `secrets` module to generate random alphanumeric codes ($62^6 \approx 56.8\text{ billion}$ combinations) with automatic collision handling.
4. **Custom Short Link Aliases (New ✨)**:
   - Create personalized, readable short links (e.g. `/my-project`, `/portfolio`).
   - Validates input format (3–30 characters, alphanumeric, `-`, `_`).
   - Protects reserved application routes (`/analytics`, `/shorten`, `/qr`, `/api`, etc.).
   - Rejects duplicate aliases with friendly error messages.
5. **QR Code Generator & Modal (New ✨)**:
   - High-contrast PNG QR codes generated on-the-fly using Python's `qrcode` library.
   - Accessible via dedicated **QR Code** buttons on both the home page and analytics dashboard.
   - Displayed in a responsive, glassmorphic modal with a direct **Download PNG** button.
   - Includes educational note on `localhost` network reachability vs. cloud deployment.
6. **7-Day Click Activity Trend Chart (New ✨)**:
   - Interactive line chart embedded into the Analytics dashboard.
   - Displays daily click volume over the last 7 calendar days aggregated from `click_logs`.
   - Built with responsive Chart.js with dark navy and purple gradients and empty-state handling.
7. **Copy to Clipboard**: One-click copying with animated visual feedback (`Copied!` checkmark) and toast notifications.
8. **Direct 302 Redirection**: Instantly forwards visitors from `/<short_code>` to the destination website.
9. **Real-Time Click Tracking**: Increments link click counters in SQLite on every visit and logs timestamps and request headers.
10. **Analytics Dashboard**: Displays total links, total clicks, top-performing links, average clicks per link, and a searchable table of individual link statistics.
11. **Parameterized SQLite Queries**: Guarantees protection against SQL Injection vulnerabilities.
12. **Polished 404 Error Page**: Friendly error handling when an unknown short link is requested.

---

## 🛠️ Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | Python 3.9+ & Flask | Routing, request processing, redirection, and validation |
| **QR Code Engine** | `qrcode` & `Pillow` | Generating scannable PNG QR codes |
| **Database** | SQLite 3 (`linkcloud.db`) | Storing links, click counters, and timestamps |
| **Frontend Structure** | HTML5 Semantic Elements | Jinja2 templated layout (`base.html`, `index.html`, etc.) |
| **Styling** | Vanilla CSS3 | Dark navy & purple glassmorphic theme, responsive layouts |
| **Data Visualization** | Chart.js | 7-day click trend graph |
| **Client Logic** | Vanilla JavaScript | Asynchronous fetch, clipboard API, modal handling, real-time search |

---

## 📁 Project Structure

```text
LinkCloud/
├── app.py                # Main Flask application, routes, QR generator, and SQLite logic
├── requirements.txt      # Python dependencies (Flask, qrcode, pillow)
├── linkcloud.db          # SQLite database (auto-created on startup)
├── .gitignore            # Git exclusion rules (virtual environments, caches, DB)
├── README.md             # Project documentation and setup guide
├── templates/            # HTML templates using Jinja2
│   ├── base.html         # Master layout with navigation, QR modal, ambient orbs, and footer
│   ├── index.html        # Home page with URL shortener, custom alias field, and result card
│   ├── analytics.html    # Analytics dashboard with metric cards, 7-day chart, and table
│   └── 404.html          # Custom 404 error page for invalid short codes
└── static/               # Static assets
    ├── css/
    │   └── style.css     # Dark navy & purple CSS design system, modal & chart styling
    └── js/
        └── main.js       # Asynchronous client logic, QR modal, Chart.js, and events
```

---

## 🗄️ Database Schema

The application uses two SQLite tables managed via parameterized queries:

### 1. `urls` Table
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Unique link identifier |
| `short_code` | `TEXT` | `UNIQUE NOT NULL` | Generated code or custom alias (e.g. `k7X9pQ` or `my-project`) |
| `original_url` | `TEXT` | `NOT NULL` | The full destination URL |
| `clicks` | `INTEGER` | `DEFAULT 0` | Total redirection counter |
| `created_at` | `TIMESTAMP`| `DEFAULT CURRENT_TIMESTAMP` | Link generation timestamp |
| `last_accessed`| `TIMESTAMP`| `NULL` | Most recent click timestamp |

### 2. `click_logs` Table
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` | Click log identifier |
| `short_code` | `TEXT` | `NOT NULL, FOREIGN KEY` | References `urls(short_code)` |
| `clicked_at` | `TIMESTAMP`| `DEFAULT CURRENT_TIMESTAMP` | Exact redirect time |
| `referrer` | `TEXT` | `NULL` | HTTP Referrer header |
| `user_agent` | `TEXT` | `NULL` | Browser User-Agent header |

---

## 🚀 How to Run the Application Locally

Follow these steps to run the application on your computer:

### 1. Open Terminal and Navigate to Directory
```bash
cd /Users/wisermonk/Documents/LinkCloud
```

### 2. Activate Python Virtual Environment
- **On macOS / Linux:**
  ```bash
  source .venv/bin/activate
  ```
- **On Windows (Command Prompt):**
  ```cmd
  .venv\Scripts\activate.bat
  ```

### 3. Install Updated Dependencies
Install Flask, qrcode, and Pillow from `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 4. Start the Application
Run the Flask server:
```bash
python3 app.py
```

> **Note on Port Conflicts (macOS AirPlay / In-Use Ports):**
> If port 5000 is occupied by another application or macOS's "AirPlay Receiver", specify an alternate port via the `PORT` environment variable:
> ```bash
> PORT=5001 python3 app.py
> ```

### 5. Access LinkCloud in Your Browser
- **Home & Shortener**: [http://127.0.0.1:5000](http://127.0.0.1:5000)
- **Analytics Dashboard**: [http://127.0.0.1:5000/analytics](http://127.0.0.1:5000/analytics)

---

## 🧪 How to Manually Test Each Feature

### Test 1: Custom Short Link Aliases
1. Open [http://127.0.0.1:5000](http://127.0.0.1:5000).
2. In the long URL field, enter: `https://github.com`.
3. In the **Custom Alias (Optional)** field, type: `my-github`.
4. Click **Shorten URL**.
5. Verify the generated short URL is `http://127.0.0.1:5000/my-github`.
6. Try repeating with the reserved alias `analytics` or `shorten`; verify a friendly error explains that the route is reserved.

### Test 2: QR Code Generator & Download
1. Click the **QR Code** button on the result card, or in the Analytics table next to any link.
2. Verify the glassmorphic modal opens with:
   - Scannable QR code preview.
   - The embedded short URL.
   - Localhost vs. cloud explanation notice.
3. Click **Download PNG** and confirm that `linkcloud-qr-<short_code>.png` downloads to your computer.

### Test 3: 7-Day Click Analytics Chart
1. Click the short link or visit `http://127.0.0.1:5000/my-github` in your browser.
2. Navigate to [http://127.0.0.1:5000/analytics](http://127.0.0.1:5000/analytics).
3. Observe the **7-Day Click Activity Trend** chart:
   - Dates are displayed along the X-axis.
   - Click count is plotted on the Y-axis.
   - Hover over the plotted point to see the interactive tooltip.
