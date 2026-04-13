#!/usr/bin/env python3
"""
Phishing Email Analyzer
========================
Analyzes raw email files (.eml or .txt) for phishing indicators and
generates a detailed report.

Usage:
    python phishing_analyzer.py <email_file>
    python phishing_analyzer.py sample_phishing.eml
    python phishing_analyzer.py --demo          # Run with a built-in sample

Dependencies (all stdlib, no pip needed):
    email, re, urllib, html, json, datetime, textwrap, sys, os
"""

import sys
import os
import re
import json
import email
import textwrap
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse
from datetime import datetime
from html.parser import HTMLParser
from collections import defaultdict


# ─────────────────────────────────────────────
#  SAMPLE PHISHING EMAIL (for --demo mode)
# ─────────────────────────────────────────────
SAMPLE_EMAIL = """\
From: "PayPal Support" <support@paypa1-secure.com>
To: victim@example.com
Subject: URGENT: Your account has been SUSPENDED! Act NOW!!!
Date: Tue, 10 Apr 2024 03:42:11 -0000
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Received: from mail.paypa1-secure.com (unknown [185.220.101.33])
    by mx.example.com (Postfix) with ESMTP id A1B2C3D4
    for <victim@example.com>; Tue, 10 Apr 2024 03:42:15 +0000 (UTC)
Received: from [10.0.0.1] (localhost [127.0.0.1])
    by mail.paypa1-secure.com (Postfix) with SMTP
X-Mailer: PHPMailer 5.2.0
X-Originating-IP: 185.220.101.33
Return-Path: bounce@spamhost.ru
Reply-To: noreply@totally-not-paypal.xyz

<html>
<body>
<p>Dear Valued Costumer,</p>

<p>We have DETECTED suspicious activty on your PayPal acount! Your account
has been temporarly SUSPENDED due to security concerns!!!</p>

<p>You must IMEDIATELY verify your informaton to avoid permanent account
closure within 24 HOURS or your funds will be FROZEN forever.</p>

<p>Click here to verify: <a href="http://paypa1-login.xyz/secure/verify?token=abc123&redirect=http://evil.ru">
https://www.paypal.com/verify-account</a></p>

<p>If you do not act within 24 hours, we will be forced to permanently
delete your account and transfer your remaining balance to our fraud
prevention fund. This is your FINAL WARNING!!!</p>

<p>Alternatively, confirm your details by replying with:
- Full Name
- Date of Birth
- Credit Card Number
- CVV / Security Code
- Social Security Number</p>

<p>Sincerely,<br>
PayPal Security Departement<br>
PayPal Inc, 2211 North First Street<br>
Tel: +1-888-555-0199</p>

<p><small>To unsibscribe from these emails click <a href="http://malware-download.ru/payload.exe">here</a></small></p>
</body>
</html>
"""


# ─────────────────────────────────────────────
#  HTML LINK EXTRACTOR
# ─────────────────────────────────────────────
class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []  # (display_text, href)
        self._current_href = None
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attrs_dict = dict(attrs)
            self._current_href = attrs_dict.get("href", "")
            self._current_text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            display = "".join(self._current_text).strip()
            self.links.append((display, self._current_href))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)


# ─────────────────────────────────────────────
#  PHISHING ANALYZER
# ─────────────────────────────────────────────
class PhishingAnalyzer:
    # Common misspellings / typo-squatted domains patterns
    TYPOSQUAT_PATTERNS = [
        r'paypa[^l]', r'micros0ft', r'g00gle', r'amaz[0o]n',
        r'app[l1]e', r'faceb[0o]{2}k', r'netfl[i1]x', r'bank[0o]f',
    ]
    SUSPICIOUS_TLD = {'.ru', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz',
                      '.top', '.click', '.loan', '.win', '.racing', '.download'}
    URGENT_PATTERNS = [
        r'\bURGENT\b', r'\bIMMEDIATELY\b', r'\bACT NOW\b', r'\bFINAL WARNING\b',
        r'\bACCOUNT.{0,15}(SUSPEND|CLOS|DELET)', r'\bVERIFY.{0,15}(NOW|IMMEDIATELY)',
        r'\b24 HOURS?\b', r'\bPASSWORD.{0,15}(EXPIRE|RESET)',
        r'\bUNUSUAL ACTIVITY\b', r'\bSECURITY ALERT\b',
    ]
    SENSITIVE_DATA_REQUESTS = [
        r'\b(credit card|card number|cvv|cvc)\b',
        r'\b(social security|ssn|sin)\b',
        r'\b(password|passwd|pin)\b',
        r'\b(bank account|routing number)\b',
        r'\b(date of birth|dob)\b',
        r'\b(mother.s maiden)\b',
    ]
    GRAMMAR_CHECKS = [
        (r'\bcostumer\b', 'customer'),
        (r'\brecieve\b', 'receive'),
        (r'\boccured\b', 'occurred'),
        (r'\bimediately\b', 'immediately'),
        (r'\bactivty\b', 'activity'),
        (r'\bacount\b', 'account'),
        (r'\btemporarly\b', 'temporarily'),
        (r'\binformaton\b', 'information'),
        (r'\bdepartement\b', 'department'),
        (r'\bunsibscribe\b', 'unsubscribe'),
        (r'\bconfidental\b', 'confidential'),
        (r'\bverificaton\b', 'verification'),
    ]

    def __init__(self, raw_email: str):
        self.raw = raw_email
        self.msg = Parser(policy=policy.compat32).parsestr(raw_email)
        self.findings = defaultdict(list)  # category -> list of Finding dicts
        self.score = 0  # 0-100 phishing risk score
        self.body_text = ""
        self.body_html = ""
        self._extract_body()

    def _extract_body(self):
        if self.msg.is_multipart():
            for part in self.msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    self.body_text += part.get_payload(decode=True).decode(errors='replace')
                elif ct == "text/html":
                    self.body_html += part.get_payload(decode=True).decode(errors='replace')
        else:
            payload = self.msg.get_payload()
            if isinstance(payload, bytes):
                payload = payload.decode(errors='replace')
            ct = self.msg.get_content_type()
            if ct == "text/html":
                self.body_html = payload
            else:
                self.body_text = payload

        # Strip HTML to get plain text for analysis
        if self.body_html and not self.body_text:
            self.body_text = re.sub(r'<[^>]+>', ' ', self.body_html)

    def _add(self, category, severity, title, detail, evidence=None):
        """severity: HIGH / MEDIUM / LOW"""
        weights = {"HIGH": 15, "MEDIUM": 8, "LOW": 3}
        self.score = min(100, self.score + weights.get(severity, 5))
        self.findings[category].append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "evidence": evidence or "",
        })

    # ── Check 1: Sender / From address ────────────────────────
    def check_sender(self):
        from_raw = self.msg.get("From", "")
        reply_to = self.msg.get("Reply-To", "")
        return_path = self.msg.get("Return-Path", "")

        # Extract display name and email address
        m = re.match(r'"?([^"<]+)"?\s*<?([^>]+)>?', from_raw)
        display_name = m.group(1).strip() if m else ""
        from_addr = m.group(2).strip() if m else from_raw.strip()
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

        # Typo-squatting in sender domain
        for pat in self.TYPOSQUAT_PATTERNS:
            if re.search(pat, from_domain, re.I):
                self._add("Sender Analysis", "HIGH",
                          "Typo-squatted sender domain",
                          f"The domain '{from_domain}' appears to mimic a legitimate brand.",
                          from_addr)

        # Suspicious TLD
        for tld in self.SUSPICIOUS_TLD:
            if from_domain.endswith(tld):
                self._add("Sender Analysis", "HIGH",
                          "Suspicious sender TLD",
                          f"Domain uses high-risk TLD '{tld}'.",
                          from_addr)

        # Display name mismatch (claims to be PayPal but domain isn't)
        brand_keywords = ["paypal", "amazon", "apple", "microsoft", "google",
                          "netflix", "bank", "chase", "wellsfargo", "irs", "fedex", "ups"]
        for bk in brand_keywords:
            if bk in display_name.lower() and bk not in from_domain.lower():
                self._add("Sender Analysis", "HIGH",
                          "Display name / domain mismatch",
                          f"Sender claims to be '{display_name}' but email comes from '{from_domain}'.",
                          from_raw)

        # Reply-To differs from From
        if reply_to and reply_to.strip() != from_addr:
            rt_domain = reply_to.split("@")[-1].rstrip(">").lower()
            if rt_domain != from_domain:
                self._add("Sender Analysis", "MEDIUM",
                          "Reply-To differs from From address",
                          "Replies will go to a different address than the apparent sender.",
                          f"From: {from_addr}  |  Reply-To: {reply_to}")

        # Return-Path mismatch
        if return_path and "@" in return_path:
            rp = return_path.strip("<>")
            rp_domain = rp.split("@")[-1].lower()
            if rp_domain != from_domain:
                self._add("Sender Analysis", "MEDIUM",
                          "Return-Path domain mismatch",
                          "Bounce messages go to a different domain.",
                          f"Return-Path: {return_path}")

    # ── Check 2: Headers ──────────────────────────────────────
    def check_headers(self):
        received = self.msg.get_all("Received") or []
        x_mailer = self.msg.get("X-Mailer", "")
        x_orig_ip = self.msg.get("X-Originating-IP", "")
        auth_results = self.msg.get("Authentication-Results", "")

        # No Authentication-Results (missing SPF/DKIM/DMARC)
        if not auth_results:
            self._add("Email Headers", "MEDIUM",
                      "Missing Authentication-Results header",
                      "No SPF/DKIM/DMARC authentication results found. Legitimate bulk mailers always include these.",
                      "Header: Authentication-Results (absent)")
        else:
            if re.search(r'spf=fail', auth_results, re.I):
                self._add("Email Headers", "HIGH", "SPF check FAILED",
                          "The sending server is not authorized to send on behalf of the claimed domain.",
                          auth_results[:120])
            if re.search(r'dkim=fail', auth_results, re.I):
                self._add("Email Headers", "HIGH", "DKIM signature FAILED",
                          "Email content may have been tampered with in transit.",
                          auth_results[:120])
            if re.search(r'dmarc=fail', auth_results, re.I):
                self._add("Email Headers", "HIGH", "DMARC policy FAILED",
                          "The email failed the sender domain's own anti-spoofing policy.",
                          auth_results[:120])

        # Suspicious X-Mailer (bulk/spam tools)
        suspicious_mailers = ["phpmailer", "massmailer", "sendblaster", "mailchimp"]
        for sm in suspicious_mailers:
            if sm in x_mailer.lower():
                self._add("Email Headers", "MEDIUM",
                          "Suspicious X-Mailer detected",
                          f"Email sent via '{x_mailer}' — commonly used in phishing campaigns.",
                          x_mailer)

        # Originating IP on blocklist indicators (simplified)
        if x_orig_ip:
            self._add("Email Headers", "LOW",
                      "X-Originating-IP present",
                      f"Email originated from IP {x_orig_ip}. Consider checking against threat intel feeds.",
                      x_orig_ip)

        # Unusual send time (3-6 AM UTC — common for automated spam)
        date_str = self.msg.get("Date", "")
        if date_str:
            m = re.search(r'(\d{2}):(\d{2}):\d{2}', date_str)
            if m:
                hour = int(m.group(1))
                if 2 <= hour <= 6:
                    self._add("Email Headers", "LOW",
                              "Email sent at unusual hour",
                              f"Sent at {m.group(1)}:{m.group(2)} UTC — automated spam often runs at off-hours.",
                              f"Date: {date_str}")

        # Received chain consistency
        if len(received) >= 2:
            servers = [re.search(r'from\s+(\S+)', r, re.I) for r in received]
            server_names = [s.group(1) for s in servers if s]
            # Check if originating server differs drastically from claimed domain
            from_domain = (self.msg.get("From", "") or "").split("@")[-1].rstrip(">").lower()
            if server_names and from_domain:
                last_server = server_names[-1].lower()
                if from_domain not in last_server and last_server not in from_domain:
                    self._add("Email Headers", "MEDIUM",
                              "Received chain inconsistency",
                              f"Email claims to be from '{from_domain}' but originated from '{last_server}'.",
                              f"Originating server: {last_server}")

    # ── Check 3: URLs / Links ─────────────────────────────────
    def check_links(self):
        # Extract links from HTML body
        parser = LinkExtractor()
        parser.feed(self.body_html or "")
        html_links = parser.links

        # Also find raw URLs in plain text
        raw_urls = re.findall(r'https?://[^\s<>"\']+', self.body_text + self.body_html)

        # Check for URL/display text mismatch
        for display, href in html_links:
            if not href:
                continue
            # Clean up href
            href_clean = href.strip()
            href_parsed = urlparse(href_clean)
            href_domain = href_parsed.netloc.lower()

            # Does link text look like a URL but differs from actual href?
            if re.match(r'https?://', display):
                display_domain = urlparse(display).netloc.lower()
                if display_domain and href_domain and display_domain != href_domain:
                    self._add("Suspicious Links", "HIGH",
                              "Mismatched URL (link text vs. actual href)",
                              f"Displayed URL points to '{display_domain}' but actually goes to '{href_domain}'.",
                              f"Text: {display[:80]}\nHref: {href_clean[:80]}")

            # Suspicious href TLD
            for tld in self.SUSPICIOUS_TLD:
                if href_domain.endswith(tld):
                    self._add("Suspicious Links", "HIGH",
                              "Link to suspicious TLD",
                              f"Hyperlink leads to a high-risk domain extension '{tld}'.",
                              href_clean[:100])

            # Executable file download links
            if re.search(r'\.(exe|bat|cmd|ps1|vbs|js|msi|dmg|sh)(\?|$)', href_clean, re.I):
                self._add("Suspicious Links", "HIGH",
                          "Link points to executable file",
                          "A link in the email downloads an executable — classic malware delivery.",
                          href_clean[:100])

            # IP address instead of domain
            if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', href_clean):
                self._add("Suspicious Links", "HIGH",
                          "Link uses raw IP address",
                          "Legitimate services never link directly to IP addresses.",
                          href_clean[:100])

            # Redirect chains / double URL encoding
            if href_clean.count("http") > 1 or "redirect" in href_clean.lower():
                self._add("Suspicious Links", "MEDIUM",
                          "URL redirection detected",
                          "Link contains a redirect, possibly to obfuscate the true destination.",
                          href_clean[:100])

            # Typo-squatted link domain
            for pat in self.TYPOSQUAT_PATTERNS:
                if re.search(pat, href_domain, re.I):
                    self._add("Suspicious Links", "HIGH",
                              "Typo-squatted link domain",
                              f"Link domain '{href_domain}' mimics a trusted brand.",
                              href_clean[:100])

        # Count total links
        if len(raw_urls) > 5:
            self._add("Suspicious Links", "LOW",
                      f"High number of URLs ({len(raw_urls)})",
                      "Many links in a single email can indicate bulk phishing.",
                      f"{len(raw_urls)} URLs found")

    # ── Check 4: Content / Body ───────────────────────────────
    def check_content(self):
        text = self.body_text.upper()
        raw_text = self.body_text

        # Urgent/threatening language
        found_urgent = []
        for pat in self.URGENT_PATTERNS:
            if re.search(pat, text, re.I):
                m = re.search(pat, raw_text, re.I)
                found_urgent.append(m.group(0) if m else pat)

        if found_urgent:
            self._add("Content Analysis", "HIGH",
                      "Urgent / threatening language detected",
                      "Phishing emails create artificial urgency to bypass rational thinking.",
                      " | ".join(found_urgent[:5]))

        # Requests for sensitive data
        found_sensitive = []
        for pat in self.SENSITIVE_DATA_REQUESTS:
            if re.search(pat, raw_text, re.I):
                m = re.search(pat, raw_text, re.I)
                found_sensitive.append(m.group(0) if m else pat)

        if found_sensitive:
            self._add("Content Analysis", "HIGH",
                      "Requests for sensitive personal data",
                      "Legitimate companies never ask for passwords, SSN, or card details via email.",
                      " | ".join(found_sensitive))

        # Excessive exclamation marks
        excl_count = raw_text.count("!")
        if excl_count >= 3:
            self._add("Content Analysis", "MEDIUM",
                      f"Excessive exclamation marks ({excl_count})",
                      "Overuse of '!' is a common manipulative tactic in phishing.",
                      f"{excl_count} exclamation marks found")

        # ALL CAPS words
        caps_words = re.findall(r'\b[A-Z]{4,}\b', raw_text)
        caps_unique = list(set(caps_words))
        if len(caps_unique) >= 3:
            self._add("Content Analysis", "LOW",
                      f"Excessive use of ALL CAPS ({len(caps_unique)} words)",
                      "ALL CAPS text is used to create panic and urgency.",
                      ", ".join(caps_unique[:8]))

    # ── Check 5: Spelling & Grammar ───────────────────────────
    def check_spelling(self):
        errors_found = []
        for pat, correct in self.GRAMMAR_CHECKS:
            if re.search(pat, self.body_text, re.I):
                m = re.search(pat, self.body_text, re.I)
                errors_found.append(f"'{m.group(0)}' → should be '{correct}'")

        if errors_found:
            self._add("Spelling & Grammar", "MEDIUM",
                      f"{len(errors_found)} spelling/grammar error(s) detected",
                      "Professional companies proofread communications; errors indicate non-native or automated content.",
                      "\n".join(errors_found))

    # ── Check 6: Attachments ──────────────────────────────────
    def check_attachments(self):
        dangerous_ext = {'.exe', '.bat', '.cmd', '.vbs', '.js', '.jar',
                         '.ps1', '.scr', '.msi', '.com', '.pif', '.wsf'}
        disguised_ext = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar'}

        for part in self.msg.walk():
            filename = part.get_filename()
            if not filename:
                continue
            ext = os.path.splitext(filename)[-1].lower()

            if ext in dangerous_ext:
                self._add("Attachments", "HIGH",
                          f"Dangerous attachment: {filename}",
                          "Executable attachments are the primary malware delivery vector.",
                          filename)
            elif ext in disguised_ext:
                self._add("Attachments", "MEDIUM",
                          f"Potentially malicious attachment: {filename}",
                          "Office documents and archives can contain macros or embedded malware.",
                          filename)
            # Double extension (e.g. invoice.pdf.exe)
            if filename.count(".") > 1:
                self._add("Attachments", "HIGH",
                          f"Double-extension filename: {filename}",
                          "Double extensions (e.g. .pdf.exe) disguise executables as documents.",
                          filename)

    # ── Main analysis ─────────────────────────────────────────
    def analyze(self):
        self.check_sender()
        self.check_headers()
        self.check_links()
        self.check_content()
        self.check_spelling()
        self.check_attachments()
        return self

    # ── Risk level string ─────────────────────────────────────
    @property
    def risk_level(self):
        if self.score >= 60:   return "CRITICAL"
        if self.score >= 40:   return "HIGH"
        if self.score >= 20:   return "MEDIUM"
        if self.score >= 5:    return "LOW"
        return "CLEAN"

    # ── Report generator ──────────────────────────────────────
    def generate_report(self) -> str:
        lines = []
        w = 70

        def hdr(title, char="═"):
            lines.append(char * w)
            lines.append(f"  {title}")
            lines.append(char * w)

        def sub(title):
            lines.append(f"\n{'─' * w}")
            lines.append(f"  {title}")
            lines.append('─' * w)

        hdr("PHISHING EMAIL ANALYSIS REPORT")
        lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Analyzer  : PhishingAnalyzer v1.0")
        lines.append("")

        # Email metadata
        sub("EMAIL METADATA")
        meta_fields = ["From", "To", "Subject", "Date", "Reply-To", "Return-Path"]
        for f in meta_fields:
            val = self.msg.get(f, "(not present)")
            lines.append(f"  {f:<15}: {val}")

        # Risk summary
        sub("RISK ASSESSMENT")
        bar_fill = int(self.score / 100 * 40)
        bar = "█" * bar_fill + "░" * (40 - bar_fill)
        lines.append(f"  Phishing Score : {self.score}/100")
        lines.append(f"  [{bar}]")
        lines.append(f"  Risk Level     : *** {self.risk_level} ***")
        lines.append("")

        total = sum(len(v) for v in self.findings.values())
        sev_counts = defaultdict(int)
        for items in self.findings.values():
            for item in items:
                sev_counts[item["severity"]] += 1

        lines.append(f"  Total indicators : {total}")
        lines.append(f"  ├── HIGH     : {sev_counts['HIGH']}")
        lines.append(f"  ├── MEDIUM   : {sev_counts['MEDIUM']}")
        lines.append(f"  └── LOW      : {sev_counts['LOW']}")

        # Detailed findings
        sub("DETAILED FINDINGS")
        sev_icon = {"HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[-]"}

        for category, items in self.findings.items():
            lines.append(f"\n  ◈ {category.upper()}")
            for item in items:
                icon = sev_icon.get(item["severity"], "[?]")
                lines.append(f"    {icon} [{item['severity']}] {item['title']}")
                wrapped = textwrap.fill(item["detail"], width=62,
                                        initial_indent="        ",
                                        subsequent_indent="        ")
                lines.append(wrapped)
                if item["evidence"]:
                    ev_lines = item["evidence"].split("\n")
                    for ev in ev_lines:
                        ev_wrapped = textwrap.fill(ev, width=58,
                                                   initial_indent="        Evidence: ",
                                                   subsequent_indent="                  ")
                        lines.append(ev_wrapped)
                lines.append("")

        # Recommendations
        sub("RECOMMENDATIONS")
        recs = [
            "1. DO NOT click any links in this email.",
            "2. DO NOT download or open any attachments.",
            "3. DO NOT reply with personal or financial information.",
            "4. Report the email as phishing to your email provider.",
            "5. If you clicked a link, change your passwords immediately.",
            "6. Verify suspicious requests by contacting the company",
            "   directly using their official website.",
            "7. Forward phishing emails to: reportphishing@apwg.org",
            "   (Anti-Phishing Working Group)",
        ]
        for r in recs:
            lines.append(f"  {r}")

        sub("END OF REPORT")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps({
            "metadata": {
                "from": self.msg.get("From", ""),
                "to": self.msg.get("To", ""),
                "subject": self.msg.get("Subject", ""),
                "date": self.msg.get("Date", ""),
            },
            "score": self.score,
            "risk_level": self.risk_level,
            "findings": dict(self.findings),
        }, indent=2)


# ─────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────
def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if sys.argv[1] == "--demo":
        print("[ Running in DEMO mode with built-in sample phishing email ]\n")
        raw = SAMPLE_EMAIL
    else:
        path = sys.argv[1]
        if not os.path.exists(path):
            print(f"Error: File not found: {path}")
            sys.exit(1)
        with open(path, "rb") as f:
            raw = f.read().decode(errors="replace")

    analyzer = PhishingAnalyzer(raw).analyze()
    report = analyzer.generate_report()
    print(report)

    # Optionally export JSON
    if "--json" in sys.argv:
        out = sys.argv[1].replace(".eml", "").replace(".txt", "") + "_report.json"
        if sys.argv[1] == "--demo":
            out = "phishing_report.json"
        with open(out, "w") as f:
            f.write(analyzer.to_json())
        print(f"\n[ JSON report saved to: {out} ]")


if __name__ == "__main__":
    main()
