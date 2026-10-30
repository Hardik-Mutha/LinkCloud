/**
 * LinkCloud - Vanilla JavaScript Client
 * Handles URL submission with optional custom aliases, QR Code modal generation,
 * interactive 7-day click analytics charts, clipboard copy, search, and toasts.
 */

let analyticsChartInstance = null;

document.addEventListener("DOMContentLoaded", () => {
    initShortenerForm();
    initCopyButtons();
    initPasteButton();
    initQrModal();
    initAnalyticsChart();
    initAnalyticsSearch();
    initStatsRefresh();
});

/* ==========================================================================
   Toast Notification System
   ========================================================================== */
function showToast(message, type = "success") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;

    const iconSvg = type === "success" 
        ? `<svg class="toast-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`
        : `<svg class="toast-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;

    toast.innerHTML = `
        ${iconSvg}
        <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    // Auto-remove toast after 3.2 seconds
    setTimeout(() => {
        toast.style.animation = "slideOutToast 0.25s forwards";
        setTimeout(() => toast.remove(), 250);
    }, 3200);
}

/* ==========================================================================
   Home Page: URL Shortener Form with Custom Alias Handling
   ========================================================================== */
function initShortenerForm() {
    const form = document.getElementById("shorten-form");
    const input = document.getElementById("long-url-input");
    const aliasInput = document.getElementById("custom-alias-input");
    const submitBtn = document.getElementById("submit-btn");
    const errorBanner = document.getElementById("error-banner");
    const errorMessage = document.getElementById("error-message");
    const resultCard = document.getElementById("result-card");
    const shortUrlLink = document.getElementById("short-url-link");
    const resultCode = document.getElementById("result-code");
    const originalUrlText = document.getElementById("original-url-text");
    const copyBtn = document.getElementById("copy-btn");
    const openLinkBtn = document.getElementById("open-link-btn");
    const resultQrBtn = document.getElementById("result-qr-btn");

    if (!form || !input) return;

    // Clear error message when user starts typing
    [input, aliasInput].forEach(el => {
        if (!el) return;
        el.addEventListener("input", () => {
            if (errorBanner && errorBanner.classList.contains("visible")) {
                errorBanner.classList.remove("visible");
                errorMessage.textContent = "";
            }
        });
    });

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const rawUrl = input.value.trim();
        const rawAlias = aliasInput ? aliasInput.value.trim() : "";

        // Client-side quick check
        if (!rawUrl) {
            displayError("Please enter or paste a URL before shortening.");
            input.focus();
            return;
        }

        // Show loading state
        const originalBtnHtml = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = `
            <span class="btn-text">Shortening...</span>
            <svg class="spin-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
            </svg>
        `;

        try {
            const response = await fetch("/shorten", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    url: rawUrl,
                    alias: rawAlias
                })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                const msg = data.error || "Failed to shorten the URL. Please verify the address.";
                displayError(msg);
                showToast(msg, "error");
                return;
            }

            // Success! Populate Result Card
            hideError();
            resultCode.textContent = data.short_code;
            shortUrlLink.textContent = data.short_url;
            shortUrlLink.href = data.short_url;
            originalUrlText.textContent = data.original_url;
            originalUrlText.title = data.original_url;

            if (openLinkBtn) {
                openLinkBtn.href = data.short_url;
            }

            if (copyBtn) {
                copyBtn.dataset.copyTarget = data.short_url;
                resetCopyButton(copyBtn);
            }

            if (resultQrBtn) {
                resultQrBtn.dataset.shortCode = data.short_code;
                resultQrBtn.dataset.shortUrl = data.short_url;
            }

            // Reveal Result Card with animation
            resultCard.classList.remove("visible");
            void resultCard.offsetWidth; // Trigger reflow
            resultCard.classList.add("visible");

            showToast("Short URL generated successfully!", "success");

            // Scroll result card into view smoothly
            resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });

        } catch (err) {
            console.error("Shortening error:", err);
            displayError("Network error: Could not reach the server. Is Flask running?");
            showToast("Network error. Please try again.", "error");
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnHtml;
        }
    });

    function displayError(msg) {
        if (!errorMessage || !errorBanner) return;
        errorMessage.textContent = msg;
        errorBanner.classList.add("visible");
    }

    function hideError() {
        if (!errorMessage || !errorBanner) return;
        errorBanner.classList.remove("visible");
        errorMessage.textContent = "";
    }
}

/* ==========================================================================
   Feature 1: QR Code Modal Generator & Actions
   ========================================================================== */
function initQrModal() {
    const modal = document.getElementById("qr-modal");
    if (!modal) return;

    const modalBackdrop = modal.querySelector(".modal-backdrop");
    const closeBtn = document.getElementById("modal-x-btn");
    const cancelBtn = document.getElementById("modal-cancel-btn");
    const qrImg = document.getElementById("modal-qr-img");
    const shortCodeEl = document.getElementById("modal-short-code");
    const shortUrlEl = document.getElementById("modal-short-url");
    const downloadBtn = document.getElementById("modal-download-btn");

    function openModal(shortCode, shortUrl) {
        if (!shortCode) return;

        // Set image source to Python QR code endpoint
        const qrEndpoint = `/qr/${encodeURIComponent(shortCode)}`;
        qrImg.src = qrEndpoint;

        if (shortCodeEl) shortCodeEl.textContent = shortCode;
        if (shortUrlEl) {
            shortUrlEl.textContent = shortUrl || `${window.location.origin}/${shortCode}`;
            shortUrlEl.href = shortUrl || `${window.location.origin}/${shortCode}`;
        }

        if (downloadBtn) {
            downloadBtn.href = `${qrEndpoint}?download=1`;
            downloadBtn.download = `linkcloud-qr-${shortCode}.png`;
        }

        modal.classList.add("active");
        modal.setAttribute("aria-hidden", "false");
        document.body.style.overflow = "hidden";
    }

    function closeModal() {
        modal.classList.remove("active");
        modal.setAttribute("aria-hidden", "true");
        document.body.style.overflow = "";
    }

    // Close on buttons and backdrop
    if (closeBtn) closeBtn.addEventListener("click", closeModal);
    if (cancelBtn) cancelBtn.addEventListener("click", closeModal);
    if (modalBackdrop) modalBackdrop.addEventListener("click", closeModal);

    // Close on Escape key
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && modal.classList.contains("active")) {
            closeModal();
        }
    });

    // Delegate QR button clicks (Home page result card & Analytics table inline buttons)
    document.addEventListener("click", (e) => {
        const qrBtn = e.target.closest("#result-qr-btn, .btn-qr-action, .btn-qr-inline");
        if (!qrBtn) return;

        e.preventDefault();
        const shortCode = qrBtn.dataset.shortCode || qrBtn.getAttribute("data-short-code");
        const shortUrl = qrBtn.dataset.shortUrl || qrBtn.getAttribute("data-short-url");

        if (shortCode) {
            openModal(shortCode, shortUrl);
        } else {
            showToast("No short link found to generate QR code", "error");
        }
    });
}

/* ==========================================================================
   Feature 2: Click Analytics Chart (7-Day Trend via Chart.js)
   ========================================================================== */
function initAnalyticsChart() {
    const canvas = document.getElementById("clicksChart");
    if (!canvas) return;

    const payloadEl = document.getElementById("chart-data-payload");
    let labels = [];
    let values = [];
    let totalClicks = 0;

    if (payloadEl) {
        try {
            labels = JSON.parse(payloadEl.getAttribute("data-labels") || "[]");
            values = JSON.parse(payloadEl.getAttribute("data-values") || "[]");
            totalClicks = parseInt(payloadEl.getAttribute("data-total") || "0", 10);
        } catch (err) {
            console.error("Error parsing chart payload:", err);
        }
    }

    const canvasWrapper = document.getElementById("chart-canvas-wrapper");
    const emptyBox = document.getElementById("chart-empty-state");

    // Check if Chart.js is loaded
    if (typeof Chart === "undefined") {
        console.warn("Chart.js not loaded. Skipping chart rendering.");
        return;
    }

    // Toggle empty state vs canvas
    if (totalClicks === 0 && values.every(v => v === 0)) {
        if (canvasWrapper) canvasWrapper.classList.add("hidden");
        if (emptyBox) emptyBox.classList.remove("hidden");
    } else {
        if (canvasWrapper) canvasWrapper.classList.remove("hidden");
        if (emptyBox) emptyBox.classList.add("hidden");
    }

    const ctx = canvas.getContext("2d");

    // Create glowing purple gradient
    const gradient = ctx.createLinearGradient(0, 0, 0, 220);
    gradient.addColorStop(0, "rgba(139, 92, 246, 0.45)");
    gradient.addColorStop(1, "rgba(139, 92, 246, 0.0)");

    // Destroy existing chart instance if reinitializing
    if (analyticsChartInstance) {
        analyticsChartInstance.destroy();
    }

    analyticsChartInstance = new Chart(ctx, {
        type: "line",
        data: {
            labels: labels,
            datasets: [
                {
                    label: "Daily Link Clicks",
                    data: values,
                    borderColor: "#a855f7",
                    borderWidth: 2.5,
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.35,
                    pointBackgroundColor: "#c084fc",
                    pointBorderColor: "#0f1527",
                    pointBorderWidth: 2,
                    pointRadius: 4.5,
                    pointHoverRadius: 7,
                    pointHoverBackgroundColor: "#ffffff",
                    pointHoverBorderColor: "#8b5cf6",
                    pointHoverBorderWidth: 3,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: "#131b2e",
                    titleColor: "#f8fafc",
                    bodyColor: "#c084fc",
                    borderColor: "rgba(139, 92, 246, 0.4)",
                    borderWidth: 1,
                    padding: 10,
                    cornerRadius: 8,
                    displayColors: false,
                    callbacks: {
                        label: function(context) {
                            const val = context.parsed.y;
                            return `Clicks: ${val}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: "rgba(255, 255, 255, 0.05)",
                        borderColor: "rgba(255, 255, 255, 0.1)"
                    },
                    ticks: {
                        color: "#94a3b8",
                        font: {
                            family: "'Inter', sans-serif",
                            size: 11
                        }
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: "rgba(255, 255, 255, 0.05)",
                        borderColor: "rgba(255, 255, 255, 0.1)"
                    },
                    ticks: {
                        color: "#94a3b8",
                        stepSize: 1,
                        precision: 0,
                        font: {
                            family: "'Inter', sans-serif",
                            size: 11
                        }
                    }
                }
            }
        }
    });
}

/* ==========================================================================
   Clipboard Copy Handling
   ========================================================================== */
function initCopyButtons() {
    // Handle result card copy button & table copy buttons via delegation
    document.addEventListener("click", async (e) => {
        const copyBtn = e.target.closest("#copy-btn, .btn-copy-inline");
        if (!copyBtn) return;

        e.preventDefault();
        const textToCopy = copyBtn.dataset.copyTarget || copyBtn.getAttribute("data-copy-target");

        if (!textToCopy) {
            showToast("Nothing to copy", "error");
            return;
        }

        try {
            await copyTextToClipboard(textToCopy);
            markButtonAsCopied(copyBtn);
            showToast("Copied short URL to clipboard!", "success");
        } catch (err) {
            console.error("Clipboard copy failed:", err);
            showToast("Failed to copy automatically. Please copy manually.", "error");
        }
    });
}

async function copyTextToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    }
    // Fallback for non-https / older browsers
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    textArea.style.top = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    const successful = document.execCommand("copy");
    textArea.remove();
    if (!successful) throw new Error("Fallback copy command failed");
}

function markButtonAsCopied(btn) {
    btn.classList.add("copied");
    const textSpan = btn.querySelector(".copy-text, span");
    const originalText = textSpan ? textSpan.textContent : "Copy";

    if (textSpan) {
        textSpan.textContent = "Copied!";
    }

    setTimeout(() => {
        btn.classList.remove("copied");
        if (textSpan) {
            textSpan.textContent = originalText;
        }
    }, 2000);
}

function resetCopyButton(btn) {
    btn.classList.remove("copied");
    const textSpan = btn.querySelector(".copy-text");
    if (textSpan) textSpan.textContent = "Copy URL";
}

/* ==========================================================================
   Home Page: Quick Paste Button
   ========================================================================== */
function initPasteButton() {
    const pasteBtn = document.getElementById("paste-btn");
    const input = document.getElementById("long-url-input");

    if (!pasteBtn || !input) return;

    pasteBtn.addEventListener("click", async () => {
        try {
            if (navigator.clipboard && navigator.clipboard.readText) {
                const text = await navigator.clipboard.readText();
                if (text) {
                    input.value = text.trim();
                    input.focus();
                    showToast("Pasted from clipboard", "success");
                    return;
                }
            }
            input.focus();
            showToast("Please press Ctrl+V or Cmd+V to paste.", "error");
        } catch (err) {
            input.focus();
            showToast("Please press Ctrl+V or Cmd+V to paste.", "error");
        }
    });
}

/* ==========================================================================
   Analytics Page: Live Search & Filtering
   ========================================================================== */
function initAnalyticsSearch() {
    const searchInput = document.getElementById("table-search");
    const tableBody = document.getElementById("table-body");
    const visibleCount = document.getElementById("visible-count");
    const noResults = document.getElementById("no-search-results");

    if (!searchInput || !tableBody) return;

    searchInput.addEventListener("input", () => {
        const query = searchInput.value.toLowerCase().trim();
        const rows = tableBody.querySelectorAll(".link-row");
        let matchedCount = 0;

        rows.forEach(row => {
            const searchData = (row.getAttribute("data-search") || "").toLowerCase();
            if (!query || searchData.includes(query)) {
                row.style.display = "";
                matchedCount++;
            } else {
                row.style.display = "none";
            }
        });

        if (visibleCount) {
            visibleCount.textContent = `${matchedCount} link${matchedCount === 1 ? '' : 's'} found`;
        }

        if (noResults) {
            if (matchedCount === 0 && rows.length > 0) {
                noResults.classList.remove("hidden");
            } else {
                noResults.classList.add("hidden");
            }
        }
    });
}

/* ==========================================================================
   Analytics Page: Live Stats Refresh
   ========================================================================== */
function initStatsRefresh() {
    const refreshBtn = document.getElementById("refresh-stats-btn");
    if (!refreshBtn) return;

    refreshBtn.addEventListener("click", async () => {
        const svg = refreshBtn.querySelector("svg");
        if (svg) svg.style.animation = "spin 0.7s linear infinite";

        try {
            const res = await fetch("/api/stats");
            if (!res.ok) throw new Error("Failed to fetch stats");
            const data = await res.json();

            // Update Metric Cards
            const totalLinksEl = document.getElementById("stat-total-links");
            const totalClicksEl = document.getElementById("stat-total-clicks");
            const avgClicksEl = document.getElementById("stat-avg-clicks");

            if (totalLinksEl) totalLinksEl.textContent = data.total_links;
            if (totalClicksEl) totalClicksEl.textContent = data.total_clicks;
            if (avgClicksEl) {
                const avg = data.total_links > 0 ? (data.total_clicks / data.total_links).toFixed(1) : "0.0";
                avgClicksEl.textContent = avg;
            }

            // Update chart dynamically if loaded
            if (analyticsChartInstance && data.chart_labels && data.chart_data) {
                analyticsChartInstance.data.labels = data.chart_labels;
                analyticsChartInstance.data.datasets[0].data = data.chart_data;
                analyticsChartInstance.update();

                const totalLabel = document.getElementById("chart-total-label");
                if (totalLabel) totalLabel.textContent = `${data.total_chart_clicks || 0} clicks this week`;
            }

            showToast("Analytics data refreshed!", "success");

        } catch (err) {
            console.error("Refresh error:", err);
            showToast("Failed to refresh statistics", "error");
        } finally {
            if (svg) svg.style.animation = "";
        }
    });
}

/* ==========================================================================
   Utility Helpers
   ========================================================================== */
function escapeHtml(str) {
    if (!str) return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
