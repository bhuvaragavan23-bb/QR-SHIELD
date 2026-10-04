document.addEventListener("DOMContentLoaded", function () {
    let scanner = null;
    let totalScans = 0;
    let threatsDetected = 0;
    let paymentScans = 0;
    let lastScanContent = "";
    let lastScanType = "";
    let lastScanRisk = null;
    let lastScanWarnings = [];
    let history = JSON.parse(localStorage.getItem("qrHistory") || "[]");

    const qrInput = document.getElementById("qrInput");
    const qrContent = document.getElementById("qrContent");
    const contentType = document.getElementById("contentType");
    const securityMessage = document.getElementById("securityMessage");
    const scanStatus = document.getElementById("scanStatus");

   function getType(text) {
    text = text.trim();

    // UPI payment link
    if (/^upi:\/\/pay/i.test(text)) {
        return "Payment QR";
    }

    // Normal UPI ID such as name@upi, number@ybl, shop@okaxis
    if (/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$/i.test(text)) {
        return "Payment QR";
    }

    // Website
    if (/^https?:\/\//i.test(text)) {
        return "Website URL";
    }

    // Wi-Fi
    if (/^WIFI:/i.test(text)) {
        return "Wi-Fi Network";
    }

    // Contact
    if (/^BEGIN:VCARD/i.test(text)) {
        return "Contact";
    }

    return "Plain Text";
}

   function isSuspicious(text) {
    const lower = text.toLowerCase().trim();

    const suspiciousTerms = [
        "login-verify",
        "account-verify",
        "free-money",
        "claim-prize",
        "password-reset",
        "verify-account",
        "verify",
        "login",
        "password",
        "bank",
        "kyc",
        "urgent",
        "reward",
        "winner",
        "claim",
        "security-alert"
    ];

    // Check suspicious words
    if (suspiciousTerms.some(term => lower.includes(term))) {
        return true;
    }

    try {
        const url = new URL(text);

        // HTTP is less secure than HTTPS
        if (url.protocol === "http:") {
            return true;
        }

        // Direct IP address instead of a normal domain
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
            return true;
        }

        // Username/password inside URL
        if (url.username || url.password) {
            return true;
        }

        // Common URL shorteners
        const shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "is.gd",
            "ow.ly",
            "cutt.ly",
            "shorturl.at"
        ];

        if (shorteners.includes(url.hostname.toLowerCase())) {
            return true;
        }

        // Unusual port
        if (url.port && !["80", "443"].includes(url.port)) {
            return true;
        }

    } catch (error) {
        // Not a URL — continue checking as normal text
    }

    return false;
}
    function analyzeRisk(text) {
    let score = 0;
    const reasons = [];
    const lower = text.toLowerCase().trim();

    // Suspicious words
    const suspiciousWords = [
        "login-verify",
        "account-verify",
        "free-money",
        "claim-prize",
        "password-reset",
        "verify-account",
        "login",
        "password",
        "bank",
        "kyc",
        "urgent",
        "reward",
        "winner",
        "claim",
        "security-alert"
    ];

    const foundWords = suspiciousWords.filter(word =>
        lower.includes(word)
    );

    if (foundWords.length > 0) {
        score += Math.min(foundWords.length * 10, 30);
        reasons.push(
            "Suspicious security-related words detected: " +
            foundWords.join(", ")
        );
    }

    // HTTP website
    if (/^http:\/\//i.test(text)) {
        score += 20;
        reasons.push("Website uses HTTP instead of HTTPS.");
    }

    try {
        const url = new URL(text);
        const hostname = url.hostname.toLowerCase();
const suspiciousDomainPatterns = [
    "login-",
    "-login",
    "verify-",
    "-verify",
    "secure-",
    "-secure",
    "account-",
    "-account",
    "payment-",
    "-payment",
    "bank-",
    "-bank"
];

if (
    suspiciousDomainPatterns.some(pattern =>
        hostname.includes(pattern)
    )
) {
    score += 25;
    reasons.push(
        "Domain contains a suspicious security or payment pattern."
    );
}

        // Direct IP address
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
            score += 35;
            reasons.push("Website uses a direct IP address.");
        }

        // Username or password in URL
        if (url.username || url.password) {
            score += 40;
            reasons.push("URL contains embedded login credentials.");
        }

        // URL shorteners
        const shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "is.gd",
            "ow.ly",
            "buff.ly",
            "cutt.ly",
            "shorturl.at"
        ];

        if (
            shorteners.some(domain =>
                hostname === domain ||
                hostname.endsWith("." + domain)
            )
        ) {
            score += 40;
            reasons.push("URL shortener detected.");
        }

        // Unusual port
        if (url.port && !["80", "443"].includes(url.port)) {
            score += 20;
            reasons.push(
                "Website uses an unusual network port: " + url.port
            );
        }

        // Very long URL
        if (text.length > 200) {
            score += 10;
            reasons.push("Unusually long URL detected.");
        }

        // Suspicious @ symbol
        if (text.includes("@")) {
            score += 15;
            reasons.push("URL contains an @ symbol.");
        }

    } catch (error) {
        // Not a URL; continue analysis
    }
    if (
    /^http:\/\//i.test(text) &&
    /login|verify|password|bank|kyc/i.test(text)
) {
    score += 15;
    reasons.push(
        "Multiple phishing indicators detected together."
    );
}

if (
    /^\d{1,3}(\.\d{1,3}){3}$/.test(
        (() => {
            try {
                return new URL(text).hostname;
            } catch (error) {
                return "";
            }
        })()
    ) &&
    /login|verify|password|bank|kyc/i.test(lower)
) {
    score += 15;
    reasons.push(
        "IP address combined with a sensitive action keyword."
    );
}

    // Maximum score
    score = Math.min(score, 100);

    // Risk level
    let level = "Low";

if (score >= 60) {
    level = "High";
} else if (score >= 25) {
    level = "Medium";
} else if (score > 0) {
    level = "Warning";
}

    return {
        score,
        level,
        reasons
    };
}
    function updateDashboard() {
        document.getElementById("totalScans").textContent = totalScans;
        document.getElementById("threatsDetected").textContent = threatsDetected;
        document.getElementById("paymentScans").textContent = paymentScans;
    }

    function renderHistory() {
    const list = document.getElementById("historyList");
    list.innerHTML = "";

    history.forEach(item => {
        const li = document.createElement("li");

        li.textContent = item;

        li.style.padding = "14px 16px";
        li.style.marginBottom = "10px";
        li.style.borderRadius = "10px";
        li.style.border = "1px solid rgba(0, 217, 255, 0.25)";
        li.style.background = "rgba(0, 20, 40, 0.65)";
        li.style.lineHeight = "1.6";
        li.style.wordBreak = "break-word";

        list.appendChild(li);
    });

    localStorage.setItem("qrHistory", JSON.stringify(history));
}
    function verifyQR(text) {
        text = text.trim();

        if (!text) {
            qrContent.textContent = "No QR content entered yet.";
            contentType.textContent = "";
            securityMessage.textContent = "Please enter or scan QR content.";
            return;
        } 

        const type = getType(text);
        const suspicious = isSuspicious(text);
const upiBox = document.getElementById("upiDetails");

if (type === "Payment QR") {
    const upi = analyzeUPI(text);

    upiBox.style.display = "block";

    document.getElementById("upiName").textContent =
        "Payee Name: " + (upi.name || "Not provided");

    document.getElementById("upiId").textContent =
        "UPI ID: " + (upi.id || "Not provided");

    document.getElementById("upiAmount").textContent =
        "Amount: " + (upi.amount || "Not specified");

    document.getElementById("upiCurrency").textContent =
        "Currency: " + upi.currency;
} else {
    upiBox.style.display = "none";
}
        const risk = analyzeRisk(text);
lastScanContent = text;
lastScanType = type;
lastScanRisk = risk;
lastScanWarnings = risk.reasons;
const meter = document.getElementById("riskMeterFill");

meter.style.width = risk.score + "%";

if (risk.level === "High") {
    meter.style.backgroundColor = "#ef4444";
} else if (risk.level === "Medium") {
    meter.style.backgroundColor = "#f59e0b";
} else {
    meter.style.backgroundColor = "#22c55e";
}

document.getElementById("riskScore").textContent =
    "Risk Score: " + risk.score + "/100";
const riskNumber = document.getElementById("riskNumber");

if (riskNumber) {
    riskNumber.textContent = risk.score;
}
const riskCircle = document.querySelector(".risk-circle");

if (riskCircle) {
    const angle = risk.score * 3.6;
    riskCircle.style.setProperty("--risk-angle", angle + "deg");

   if (risk.level === "High") {
    riskCircle.style.setProperty("--risk-color", "#ef4444");
} else if (risk.level === "Medium") {
    riskCircle.style.setProperty("--risk-color", "#f59e0b");
} else if (risk.level === "Warning") {
    riskCircle.style.setProperty("--risk-color", "#38bdf8");
} else {
    riskCircle.style.setProperty("--risk-color", "#22c55e");
}
}
document.getElementById("riskLevel").textContent =
    "Risk Level: " + risk.level;
const threatStatus = document.getElementById("threatStatus");
const threatDescription = document.getElementById("threatDescription");
const threatDot = document.querySelector(".threat-dot");

if (risk.level === "High") {
    threatStatus.textContent = "HIGH RISK DETECTED";
    threatDescription.textContent =
        "Suspicious QR indicators require immediate attention.";
    threatDot.style.background = "#ef4444";
    threatDot.style.boxShadow = "0 0 15px #ef4444";
    threatStatus.style.color = "#ef4444";

} else if (risk.level === "Medium") {
    threatStatus.textContent = "MEDIUM RISK";
    threatDescription.textContent =
        "Multiple suspicious indicators require verification.";
    threatDot.style.background = "#f59e0b";
    threatDot.style.boxShadow = "0 0 15px #f59e0b";
    threatStatus.style.color = "#f59e0b";

} else if (risk.level === "Warning") {
    threatStatus.textContent = "SECURITY WARNING";
    threatDescription.textContent =
        "A security indicator was detected. Review before continuing.";
    threatDot.style.background = "#38bdf8";
    threatDot.style.boxShadow = "0 0 15px #38bdf8";
    threatStatus.style.color = "#38bdf8";

} else {
    threatStatus.textContent = "LOW RISK";
    threatDescription.textContent =
        "No major suspicious indicators detected.";
    threatDot.style.background = "#22c55e";
    threatDot.style.boxShadow = "0 0 15px #22c55e";
    threatStatus.style.color = "#22c55e";
}
const riskPanel = document.getElementById("riskResult");

if (riskPanel) {
    riskPanel.classList.remove(
        "risk-low",
        "risk-medium",
        "risk-high"
    );

    if (risk.level === "High") {
    riskPanel.classList.add("risk-high");
} else if (risk.level === "Medium") {
    riskPanel.classList.add("risk-medium");
} else if (risk.level === "Warning") {
    riskPanel.classList.add("risk-warning");
} else {
    riskPanel.classList.add("risk-low");
}
}

const reasonsList = document.getElementById("riskReasons");
reasonsList.innerHTML = "";

if (risk.reasons.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No known risk indicators detected.";
    reasonsList.appendChild(item);
} else {
    risk.reasons.forEach(reason => {
        const item = document.createElement("li");
        item.textContent = reason;
        reasonsList.appendChild(item);
    });
}

        totalScans++;
        if (suspicious) threatsDetected++;
        if (type === "Payment QR") paymentScans++;

        qrContent.textContent = "QR Content: " + text;
        contentType.textContent = "Content Type: " + type;

        if (suspicious) {
            securityMessage.textContent =
                "🔴 Warning: Suspicious indicators detected. Do not proceed without checking.";
        } else if (type === "Payment QR") {
    securityMessage.textContent =
        "💳 Payment QR detected. Check the payee name, UPI ID and amount before selecting your payment app.";

        } else if (type === "Website URL") {
            securityMessage.textContent =
                "ℹ️ Website detected. HTTPS alone cannot guarantee safety.";
        } else {
            securityMessage.textContent =
                "ℹ️ Review the content carefully before continuing.";
        }

        const historyEntry =
    type + " — " + text +
    " | Risk Score: " + risk.score + "/100" +
    " | Risk Level: " + risk.level +
    " | Security Analysis: " +
    (risk.reasons.length
        ? risk.reasons.join("; ")
        : "No known risk indicators detected.");

history.unshift(historyEntry);
        history = history.slice(0, 50);

        updateDashboard();
        renderHistory();
    }
function analyzeUPI(text) {
    const details = {
        name: "",
        id: "",
        amount: "",
        currency: "INR"
    };

    text = text.trim();

    // Plain UPI ID such as shop@okaxis or number@ybl
    if (/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$/.test(text)) {
        details.id = text;
        return details;
    }

    // Full UPI payment URL
    try {
        const url = new URL(text);
        const params = url.searchParams;

        details.name = params.get("pn") || "";
        details.id = params.get("pa") || "";
        details.amount = params.get("am") || "";
        details.currency = params.get("cu") || "INR";

    } catch (error) {
        console.log("Could not read UPI details:", error);
    }

    return details;
}
    document.getElementById("verifyButton").addEventListener("click", function () {
        verifyQR(qrInput.value);
    });
document.getElementById("cancelButton").addEventListener("click", function () {
    document.getElementById("qrInput").value = "";

    document.getElementById("result").style.display = "none";

    const upiBox = document.getElementById("upiDetails");
    if (upiBox) {
        upiBox.style.display = "none";
    }
});
document.getElementById("continueButton").addEventListener("click", function () {
    const text = qrInput.value.trim();

    if (!text) {
        alert("Please verify a QR code first.");
        return;
    }

    const risk = analyzeRisk(text);

    if (risk.level === "High") {
        const proceed = confirm(
            "⚠️ HIGH RISK QR CODE\n\n" +
            "Risk Score: " + risk.score + "/100\n\n" +
            "This QR code contains suspicious indicators.\n" +
            "Are you sure you want to continue?"
        );

        if (!proceed) {
            return;
        }
    }

    alert(
        "✓ QR verification completed.\n\n" +
        "Risk Level: " + risk.level +
        "\nRisk Score: " + risk.score + "/100"
    );
});

    document.getElementById("startButton").addEventListener("click", async function () {
        if (scanner) return;

        if (typeof Html5Qrcode === "undefined") {
            scanStatus.textContent = "Scanner library did not load. Check your internet connection.";
            return;
        }

        scanner = new Html5Qrcode("reader");

        try {
            await scanner.start(
                { facingMode: "environment" },
                {
    fps: 15,
    qrbox: { width: 350, height: 350 },
    aspectRatio: 1.0,
    experimentalFeatures: {
        useBarCodeDetectorIfSupported: true
    }
},
                async function (decodedText) {
                    qrInput.value = decodedText;
                    verifyQR(decodedText);
                    await stopScanner();
                    scanStatus.textContent = "QR code scanned.";
                },
                function () {}
            );

            scanStatus.textContent = "Camera is running. Point it at a QR code.";
        } catch (error) {
            scanStatus.textContent = "Camera error: " + error;
            scanner = null;
        }
    });

    async function stopScanner() {
        if (scanner) {
            try {
                await scanner.stop();
                await scanner.clear();
            } catch (error) {
                console.log(error);
            }
            scanner = null;
        }
    }

    document.getElementById("stopButton").addEventListener("click", stopScanner);

    document.getElementById("generateButton").addEventListener("click", function () {
        const text = document.getElementById("generateInput").value.trim();
        const output = document.getElementById("qrOutput");

        output.innerHTML = "";

        if (!text) {
            output.textContent = "Please enter text or a URL.";
            return;
        }

        if (typeof QRCode === "undefined") {
            output.textContent = "QR generator library did not load. Check your internet connection.";
            return;
        }

        new QRCode(output, {
            text: text,
            width: 200,
            height: 200,
            correctLevel: QRCode.CorrectLevel.M
        });
    });
document.getElementById("exportHistory")
    .addEventListener("click", function () {
        if (history.length === 0) {
            alert("No scan history to export.");
            return;
        }

        let csv = "Scan History\n";

        history.forEach(function (item) {
            csv += '"' + item.replace(/"/g, '""') + '"\n';
        });

        const blob = new Blob([csv], {
            type: "text/csv"
        });

        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "QR_Scan_History.csv";
        link.click();

        URL.revokeObjectURL(link.href);
    });

    document.getElementById("clearHistory").addEventListener("click", function () {
        if (confirm("Clear all scan history?")) {
            history = [];
            renderHistory();
        }
    });

    document.getElementById("themeButton").addEventListener("click", function () {
        document.body.classList.toggle("light-mode");
    });

    renderHistory();
    updateDashboard();

document.getElementById("downloadReport")
    .addEventListener("click", function () {
        const report = `
QR SHIELD - SECURITY REPORT
--------------------------

Date: ${new Date().toLocaleString()}

Total Scans: ${document.getElementById("totalScans").textContent}
Threats Detected: ${document.getElementById("threatsDetected").textContent}
Payment QR Scans: ${document.getElementById("paymentScans").textContent}

LATEST QR SCAN
---------------
QR Content: ${lastScanContent || "No scan yet"}
Content Type: ${lastScanType || "N/A"}
Risk Score: ${lastScanRisk ? lastScanRisk.score + "/100" : "N/A"}
Risk Level: ${lastScanRisk ? lastScanRisk.level : "N/A"}

Security Warnings:
${lastScanWarnings.length
    ? lastScanWarnings.join("\n")
    : "No known risk indicators detected."}

Generated by QR Shield
`;
        const blob = new Blob([report], {
            type: "text/plain"
        });

        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "QR_Shield_Report.txt";
        link.click();

        URL.revokeObjectURL(link.href);

    });
});