#!/usr/bin/env python3
"""
qr_browser_analyzer_hardened.py
Defensive QR landing-page analyzer:
- Decode QR from image
- Resolve URL
- Fetch static HTML
- Load page in headless Chromium
- Capture redirects, requests, runtime script/iframe injection, storage writes,
 suspicious event listener registrations, and selected JS sink usage
- Extract forms and script URLs
- Save screenshot
- Export JSON + CSV
Install:
   pip install opencv-python requests beautifulsoup4 playwright
   playwright install chromium
   python -m playwright install chromium
Usage:
   python QR.py
"""
from __future__ import annotations
import argparse
import csv
import ctypes
import hashlib
import html as html_lib
import ipaddress
import json
import math
import os
import re
import socket
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
import cv2
import requests
from bs4 import BeautifulSoup

ANSI_ENABLED = False

TERMINAL_LOGO = r"""
              ▒███▓
            ▒██████
          ▒██████▒
        ▒██████▒
      ▒██████▒
    ▒██████▒
  ▒██████▒
▒██████▒
██████▒    ▓███░
░▓█████░   ▓███░    ░▓█▓░
  ░▓██▒           ░▓█████
                ░▓█████▓░
              ░▓█████▓░
            ░▓█████▓░
          ░▓█████▓░
        ░▓█████▓░
       ▒█████▓░
       ░███▓░
""".strip("\n")

class Color:
   RESET = "\033[0m"
   BOLD = "\033[1m"
   DIM = "\033[2m"
   RED = "\033[91m"
   GREEN = "\033[92m"
   YELLOW = "\033[93m"
   BLUE = "\033[94m"
   MAGENTA = "\033[95m"
   CYAN = "\033[96m"
   WHITE = "\033[97m"

def enable_ansi_colors() -> None:
   global ANSI_ENABLED
   if ANSI_ENABLED:
       return
   try:
       try:
           sys.stdout.reconfigure(encoding="utf-8")
           sys.stderr.reconfigure(encoding="utf-8")
       except Exception:
           pass
       if os.name == "nt":
           kernel32 = ctypes.windll.kernel32
           handle = kernel32.GetStdHandle(-11)
           mode = ctypes.c_uint32()
           if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
               kernel32.SetConsoleMode(handle, mode.value | 0x0004)
       ANSI_ENABLED = True
   except Exception:
       ANSI_ENABLED = False

def colorize(text: str, *styles: str) -> str:
   if not ANSI_ENABLED or not styles:
       return text
   return "".join(styles) + text + Color.RESET

def severity_color(severity: str) -> str:
   value = severity.lower()
   if value == "high":
       return Color.RED
   if value == "medium":
       return Color.YELLOW
   if value == "low":
       return Color.CYAN
   return Color.WHITE

def verdict_color(verdict: str) -> str:
   if "HIGH" in verdict:
       return Color.RED
   if "MEDIUM" in verdict:
       return Color.YELLOW
   return Color.GREEN

def load_banner_art(filename: str, fallback: str) -> str:
   path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
   try:
       with open(path, "r", encoding="utf-8") as f:
           content = f.read().rstrip("\n")
       return content or fallback
   except OSError:
       return fallback

@dataclass
class Finding:
   severity: str
   category: str
   message: str
   weight: int
   evidence_samples: List[str] = field(default_factory=list)
   confidence: str = "medium"
   finding_id: str = ""
   rationale: str = ""

@dataclass
class NetworkRecord:
   method: str
   url: str
   resource_type: str = ""
   status: Optional[int] = None
   from_domain: str = ""
   to_domain: str = ""

@dataclass
class FormRecord:
   action: str
   method: str
   input_types: List[str]
   input_names: List[str]
   external_action: bool = False

@dataclass
class BrowserTelemetry:
   initial_url: str = ""
   final_url: str = ""
   document_url_changes: List[str] = field(default_factory=list)
   console_messages: List[str] = field(default_factory=list)
   requests: List[NetworkRecord] = field(default_factory=list)
   failed_requests: List[str] = field(default_factory=list)
   dynamic_scripts: List[str] = field(default_factory=list)
   dynamic_iframes: List[str] = field(default_factory=list)
   storage_events: List[str] = field(default_factory=list)
   listener_events: List[str] = field(default_factory=list)
   suspicious_runtime_hits: List[str] = field(default_factory=list)
   page_title: str = ""
   html: str = ""
   screenshot_path: str = ""

@dataclass
class AnalysisResult:
   qr_value: str = ""
   initial_url: str = ""
   final_url: str = ""
   redirects: List[str] = field(default_factory=list)
   http_status: Optional[int] = None
   findings: List[Finding] = field(default_factory=list)
   browser: Optional[BrowserTelemetry] = None
   forms: List[FormRecord] = field(default_factory=list)
   script_urls: List[str] = field(default_factory=list)
   analysis_mode: str = "offline"
   image_sha256: str = ""
   started_at: str = ""
   completed_at: str = ""
   notes: List[str] = field(default_factory=list)
   @property
   def score(self) -> int:
        confidence_factor = {"high": 1.0, "medium": 0.65, "low": 0.3}
        category_caps = {
            "url": 25, "transport": 8, "redirects": 20, "phishing": 35,
            "content": 12, "scripts": 8, "javascript": 18, "keylogging": 20,
            "obfuscation": 18, "runtime": 24, "runtime-js": 22,
            "correlation": 40, "network": 12, "browser": 8, "qr": 25,
        }
        totals: Dict[str, float] = {}
        for finding in self.findings:
            contribution = finding.weight * confidence_factor.get(finding.confidence, 0.65)
            totals[finding.category] = totals.get(finding.category, 0.0) + contribution
        capped = sum(min(value, category_caps.get(category, 15)) for category, value in totals.items())
        corroborated_categories = {
            f.category for f in self.findings
            if f.confidence == "high" and f.severity in {"high", "critical"}
        }
        if len(corroborated_categories) >= 3:
            capped += 10
        return min(100, round(capped))
   @property
   def verdict(self) -> str:
        s = self.score
        high_confidence_high = sum(
            1 for f in self.findings
            if f.confidence == "high" and f.severity in {"high", "critical"}
        )
        if s >= 70 and high_confidence_high >= 2:
            return "HIGH RISK"
        if s >= 35 or high_confidence_high >= 1:
            return "SUSPICIOUS"
        if self.analysis_mode == "offline":
            return "NO VERDICT - OFFLINE REVIEW"
        return "LOW RISK / REVIEW"
   @property
   def confidence(self) -> str:
        if self.analysis_mode == "offline":
            return "limited"
        high = sum(1 for f in self.findings if f.confidence == "high")
        medium = sum(1 for f in self.findings if f.confidence == "medium")
        return "high" if high >= 2 else "medium" if high or medium >= 2 else "low"

def clip_evidence(text: str, limit: int = 160) -> str:
   compact = re.sub(r"\s+", " ", str(text)).strip()
   if len(compact) <= limit:
       return compact
   return compact[: limit - 3] + "..."

def summarize_long_token(text: str, head: int = 48, tail: int = 24) -> str:
   compact = re.sub(r"\s+", "", str(text)).strip()
   if len(compact) <= head + tail + 3:
       return compact
   return f"{compact[:head]}...{compact[-tail:]} (len={len(compact)})"

def extract_regex_snippets(text: str, pattern: str, max_items: int = 2, radius: int = 80) -> List[str]:
   snippets: List[str] = []
   for match in re.finditer(pattern, text, flags=re.I):
       start = max(0, match.start() - radius)
       end = min(len(text), match.end() + radius)
       snippet = text[start:end]
       snippets = merge_evidence(snippets, [snippet], max_items=max_items)
       if len(snippets) >= max_items:
           break
   return snippets

def top_entropy_script_chunks(scripts: List[str], max_items: int = 2) -> List[str]:
   ranked = [
       (shannon_entropy(script), script)
       for script in scripts
       if script and script.strip()
   ]
   ranked.sort(key=lambda item: item[0], reverse=True)
   return [script for _, script in ranked[:max_items]]

def extract_inline_script_texts(html: str) -> List[str]:
   if not html:
       return []
   soup = BeautifulSoup(html, "html.parser")
   scripts: List[str] = []
   for script in soup.find_all("script"):
       if not script.get("src"):
           text = script.get_text("\n", strip=False)
           if text and text.strip():
               scripts.append(text)
   return scripts

def runtime_hit_evidence_from_html(html: str, hit: str) -> List[str]:
   inline_scripts = extract_inline_script_texts(html)
   combined_script = "\n".join(inline_scripts)
   low = hit.lower()
   if "eval" in low:
       return extract_regex_snippets(combined_script, r"\beval\s*\(", max_items=2)
   if "function constructor" in low:
       return extract_regex_snippets(combined_script, r"new\s+Function\s*\(", max_items=2)
   if "sendbeacon" in low:
       return extract_regex_snippets(combined_script, r"\bnavigator\.sendBeacon\s*\(", max_items=2)
   if "document.write" in low:
       return extract_regex_snippets(combined_script, r"\bdocument\.write\s*\(", max_items=2)
   return []

def merge_evidence(existing: List[str], new_items: Optional[List[str]], max_items: int = 2) -> List[str]:
   merged = list(existing)
   for item in new_items or []:
       clipped = clip_evidence(item)
       if clipped and clipped not in merged:
           merged.append(clipped)
       if len(merged) >= max_items:
           break
   return merged

def add_finding(
   result: AnalysisResult,
   severity: str,
   category: str,
   message: str,
   weight: int,
   evidence_samples: Optional[List[str]] = None,
   confidence: str = "medium",
   rationale: str = "",
   finding_id: str = "",
) -> None:
   result.findings.append(
       Finding(
           severity=severity,
           category=category,
           message=message,
            weight=weight,
            evidence_samples=merge_evidence([], evidence_samples),
            confidence=confidence,
            rationale=rationale,
            finding_id=finding_id or f"{category.upper()}-{len(result.findings) + 1:03d}",
        )
   )

def get_domain(url: str) -> str:
   return (urlparse(url).hostname or "").lower()

def is_ip_host(host: str) -> bool:
   try:
       ipaddress.ip_address(host)
       return True
   except ValueError:
       return False

def is_http_url(value: str) -> bool:
   try:
       p = urlparse(value)
       return p.scheme in {"http", "https"} and bool(p.netloc)
   except Exception:
       return False

def classify_network_target(url: str) -> tuple[bool, str, List[str]]:
   """Resolve a URL and reject destinations that could reach the analyst's local network."""
   parsed = urlparse(url)
   host = parsed.hostname or ""
   if parsed.scheme not in {"http", "https"} or not host:
       return False, "Only HTTP and HTTPS URLs with a hostname are allowed", []
   try:
       default_port = 443 if parsed.scheme == "https" else 80
       addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, parsed.port or default_port)})
   except socket.gaierror as exc:
       return False, f"Hostname resolution failed: {exc}", []
   for address in addresses:
       ip = ipaddress.ip_address(address)
       if not ip.is_global:
           return False, f"Destination resolves to non-public address {ip}", addresses
   return True, "Destination resolves only to public addresses", addresses

def require_public_network_target(url: str) -> List[str]:
   allowed, reason, addresses = classify_network_target(url)
   if not allowed:
       raise ValueError(f"Blocked network target: {reason}")
   return addresses

def file_sha256(path: str) -> str:
   digest = hashlib.sha256()
   with open(path, "rb") as handle:
       for chunk in iter(lambda: handle.read(1024 * 1024), b""):
           digest.update(chunk)
   return digest.hexdigest()

def domain_mismatch(url_a: str, url_b: str) -> bool:
   ha = get_domain(url_a)
   hb = get_domain(url_b)
   return bool(ha and hb and ha != hb)

def shannon_entropy(text: str) -> float:
   if not text:
       return 0.0
   counts = Counter(text)
   length = len(text)
   return -sum((count / length) * math.log2(count / length) for count in counts.values())

def safe_get(url: str, max_bytes: int = 2_000_000) -> tuple[requests.Response, str]:
   headers = {
       "User-Agent": "Mozilla/5.0 (compatible; QR-Vamp/2.0; defensive-use)"
   }
   session = requests.Session()
   session.trust_env = False
   history: List[requests.Response] = []
   current_url = url
   resp: requests.Response
   for _ in range(6):
       require_public_network_target(current_url)
       resp = session.get(
           current_url,
           headers=headers,
           timeout=(6, 12),
           allow_redirects=False,
           stream=True,
       )
       if resp.is_redirect or resp.is_permanent_redirect:
           location = resp.headers.get("Location")
           if not location:
               break
           history.append(resp)
           current_url = urljoin(current_url, location)
           resp.close()
           continue
       break
   else:
       raise requests.exceptions.TooManyRedirects("More than five redirects")
   resp.history = history
   resp.raise_for_status()
   content = bytearray()
   for chunk in resp.iter_content(chunk_size=8192):
       if chunk:
           content.extend(chunk)
       if len(content) >= max_bytes:
           break
   text = content.decode(resp.encoding or "utf-8", errors="replace")
   return resp, text

def dedupe_preserve(seq: List[str]) -> List[str]:
   seen: Set[str] = set()
   out: List[str] = []
   for x in seq:
       if x not in seen:
           seen.add(x)
           out.append(x)
   return out

def looks_randomish_label(host: str) -> bool:
   labels = host.split(".")
   for label in labels:
       if len(label) >= 14:
           letters = sum(c.isalpha() for c in label)
           digits = sum(c.isdigit() for c in label)
           if letters >= 6 and digits >= 3:
               return True
   return False

def count_suspicious_tlds(host: str) -> bool:
   risky = {".xyz", ".top", ".click", ".shop", ".site", ".online", ".live", ".quest", ".rest", ".buzz"}
   return any(host.endswith(tld) for tld in risky)

def _decode_with_opencv_variants(img) -> str:
   detector = cv2.QRCodeDetector()
   variants = [img]

   gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
   variants.append(gray)
   variants.append(cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC))
   variants.append(cv2.resize(gray, None, fx=3, fy=3, interpolation=cv2.INTER_CUBIC))

   otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
   variants.append(otsu)
   variants.append(cv2.resize(otsu, None, fx=2, fy=2, interpolation=cv2.INTER_NEAREST))

   blurred = cv2.GaussianBlur(gray, (5, 5), 0)
   variants.append(cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1])

   for variant in variants:
       data, _, _ = detector.detectAndDecode(variant)
       if data:
           return data.strip()

   retval, decoded_info, _, _ = detector.detectAndDecodeMulti(img)
   if retval:
       for item in decoded_info:
           if item:
               return item.strip()
   return ""

def _decode_with_pyzbar_fallback(img) -> str:
   try:
       from pyzbar.pyzbar import decode as pyzbar_decode
   except Exception:
       return ""

   decoded = pyzbar_decode(img)
   for item in decoded:
       try:
           return item.data.decode("utf-8", errors="replace").strip()
       except Exception:
           continue
   return ""

def decode_qr_image(image_path: str) -> str:
   img = cv2.imread(image_path)
   if img is None:
       raise FileNotFoundError(f"Could not read image: {image_path}")
   data = _decode_with_opencv_variants(img)
   if data:
       return data

   fallback_data = _decode_with_pyzbar_fallback(img)
   if fallback_data:
       return fallback_data

   detector = cv2.QRCodeDetector()
   _, points = detector.detect(img)
   if points is not None:
       raise ValueError(
           "QR code detected, but the payload could not be decoded. "
           "The code may be stylized, low-quality, partially obscured, or invalid."
       )
   raise ValueError("No QR code found in the image.")

SUSPICIOUS_JS_PATTERNS = [
   (r"\beval\s*\(", "Use of eval()", 18),
   (r"new\s+Function\s*\(", "Use of Function constructor", 16),
   (r"\bsetTimeout\s*\(\s*[\"']", "String-based setTimeout()", 12),
   (r"\bsetInterval\s*\(\s*[\"']", "String-based setInterval()", 12),
   (r"\bdocument\.write\s*\(", "Use of document.write()", 8),
   (r"\batob\s*\(", "Base64 decode via atob()", 8),
   (r"\bunescape\s*\(", "Use of unescape()", 8),
   (r"String\.fromCharCode\s*\(", "String.fromCharCode() often used in obfuscation", 10),
   (r"\\x[0-9a-fA-F]{2}", "Hex-escaped strings in script", 10),
   (r"\\u[0-9a-fA-F]{4}", "Unicode-escaped strings in script", 8),
   (r"\bXMLHttpRequest\b", "XHR usage", 4),
   (r"\bfetch\s*\(", "fetch() network calls", 4),
   (r"\bnavigator\.sendBeacon\s*\(", "sendBeacon() pattern", 15),
   (r"new\s+Image\s*\(\)\.src\s*=", "Image beacon pattern", 14),
   (r"\bWebSocket\s*\(", "WebSocket usage", 8),
]
KEYLOGGING_PATTERNS = [
   (r"addEventListener\s*\(\s*[\"']keydown[\"']", "keydown listener", 18),
   (r"addEventListener\s*\(\s*[\"']keypress[\"']", "keypress listener", 18),
   (r"addEventListener\s*\(\s*[\"']keyup[\"']", "keyup listener", 14),
   (r"\bonkeydown\s*=", "inline onkeydown handler", 14),
   (r"\bonkeypress\s*=", "inline onkeypress handler", 14),
   (r"\bonkeyup\s*=", "inline onkeyup handler", 12),
   (r"document\.addEventListener\s*\(\s*[\"']paste[\"']", "paste listener", 8),
   (r"document\.addEventListener\s*\(\s*[\"']input[\"']", "global input listener", 8),
]
PHISHING_KEYWORDS = [
   "login", "sign in", "signin", "verify", "verification",
   "account", "password", "passcode", "wallet", "seed phrase",
   "recovery phrase", "2fa", "otp", "bank", "secure", "unlock"
]
COMMON_WEB_SERVICE_SUFFIXES = {
   "cloudflareinsights.com", "googleapis.com", "gstatic.com", "google.com",
   "cloudflare.com", "jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
}

def is_common_web_service(host: str) -> bool:
   host = host.lower().rstrip(".")
   return any(host == suffix or host.endswith("." + suffix) for suffix in COMMON_WEB_SERVICE_SUFFIXES)

def analyze_url_structure(result: AnalysisResult, url: str) -> None:
   parsed = urlparse(url)
   host = (parsed.hostname or "").lower()
   if not host:
       add_finding(result, "high", "url", "URL has no valid hostname", 25)
       return
   if is_ip_host(host):
       add_finding(result, "medium", "url", "URL uses a raw IP address instead of a domain", 12)
   if "@" in parsed.netloc:
       add_finding(result, "high", "url", "URL contains '@' in authority section", 20)
   email_like = re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", f"{parsed.path}?{parsed.query}", flags=re.I)
   if email_like:
       add_finding(
           result, "medium", "url", "URL embeds an email address in its path or query", 10,
           evidence_samples=email_like[:2], confidence="medium",
           rationale="Personalized phishing links commonly place the intended recipient identifier directly in the URL.",
       )
   if host.startswith("xn--"):
       add_finding(result, "medium", "url", "Punycode domain detected", 10)
   if len(host.split(".")) >= 5:
       add_finding(result, "medium", "url", "Very deep subdomain chain", 8)
   if parsed.scheme != "https":
       add_finding(result, "medium", "transport", "Page is not using HTTPS", 12)
   if looks_randomish_label(host):
       add_finding(result, "low", "url", "Hostname contains random-looking label", 5)
   if count_suspicious_tlds(host):
       add_finding(result, "low", "url", "Hostname uses commonly abused TLD", 5)

def analyze_redirects(result: AnalysisResult) -> None:
   if len(result.redirects) >= 3:
       add_finding(result, "medium", "redirects", f"Multiple redirects observed ({len(result.redirects)})", 8)
   if result.initial_url and result.final_url and domain_mismatch(result.initial_url, result.final_url):
       add_finding(result, "high", "redirects", "Final landing domain differs from QR domain", 18)

def extract_forms_and_scripts(html: str, base_url: str) -> tuple[List[FormRecord], List[str]]:
   soup = BeautifulSoup(html, "html.parser")
   forms: List[FormRecord] = []
   for form in soup.find_all("form"):
       action = (form.get("action") or "").strip()
       method = (form.get("method") or "GET").upper()
       action_url = urljoin(base_url, action) if action else base_url
       external_action = domain_mismatch(base_url, action_url)
       input_types: List[str] = []
       input_names: List[str] = []
       for inp in form.find_all("input"):
           input_types.append((inp.get("type") or "text").lower())
           input_names.append(inp.get("name") or "")
       forms.append(
           FormRecord(
               action=action_url,
               method=method,
               input_types=input_types,
               input_names=input_names,
               external_action=external_action,
           )
       )
   scripts: List[str] = []
   for script in soup.find_all("script", src=True):
       scripts.append(urljoin(base_url, script["src"]))
   return forms, dedupe_preserve(scripts)

def analyze_html(result: AnalysisResult, html: str, base_url: str) -> None:
   soup = BeautifulSoup(html, "html.parser")
   text = soup.get_text(" ", strip=True).lower()
   forms, scripts = extract_forms_and_scripts(html, base_url)
   if forms:
       result.forms.extend(forms)
   result.script_urls.extend(scripts)
   password_fields = soup.find_all("input", {"type": re.compile(r"password", re.I)})
   if password_fields:
       add_finding(
           result, "low", "phishing", "Page contains password input fields", 5,
           confidence="low",
           rationale="Password fields are common; this becomes meaningful only with suspicious form routing or exfiltration behavior.",
       )
   for form in forms:
       if form.external_action:
           add_finding(result, "high", "phishing", f"Form posts to a different domain: {form.action}", 20)
       if "password" in form.input_types and "email" in form.input_types:
           add_finding(
               result, "medium", "phishing", "Form collects both email and password", 8,
               confidence="medium",
           rationale="Credential collection also appears on legitimate login pages, so other warning signs are required.",
           )
   iframes = soup.find_all("iframe")
   if len(iframes) >= 3:
       add_finding(result, "medium", "dom", f"Page contains many iframes ({len(iframes)})", 8)
   for iframe in iframes:
       style = (iframe.get("style") or "").lower()
       width = str(iframe.get("width") or "")
       height = str(iframe.get("height") or "")
       if "display:none" in style or width == "0" or height == "0":
           add_finding(result, "medium", "dom", "Hidden or zero-sized iframe detected", 10)
           break
   keyword_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in text)
   if keyword_hits >= 4:
       add_finding(result, "medium", "content", "Page contains many credential/account-related keywords", 8)
   for src in scripts:
       script_host = get_domain(src)
       if domain_mismatch(base_url, src) and not is_common_web_service(script_host):
           add_finding(
               result,
               "low",
               "scripts",
               f"External script from different domain: {src}",
               2,
               evidence_samples=[src],
               confidence="low",
               rationale="Third-party scripts are common; this signal contributes only weakly by itself.",
           )
   inline_scripts = []
   for script in soup.find_all("script"):
       if not script.get("src"):
           inline_scripts.append(script.get_text("\n", strip=False))
   combined_script = "\n".join(inline_scripts)
   for pattern, desc, weight in SUSPICIOUS_JS_PATTERNS:
       samples = extract_regex_snippets(combined_script, pattern, max_items=2)
       if samples:
           weak_pattern = any(term in desc.lower() for term in ["xhr", "fetch", "document.write", "atob", "unicode"])
           add_finding(
               result, "low" if weak_pattern else "medium", "javascript", desc,
               min(weight, 8) if weak_pattern else weight,
               evidence_samples=samples,
               confidence="low" if weak_pattern else "medium",
               rationale="This JavaScript behavior is common, so it receives a low score unless other suspicious behavior is also found.",
           )
   keylog_hits = 0
   keylog_samples: List[str] = []
   for pattern, desc, weight in KEYLOGGING_PATTERNS:
       match = re.search(pattern, combined_script, flags=re.I)
       if match:
           keylog_hits += 1
           keylog_samples.append(match.group(0))
           add_finding(
               result, "low", "keylogging", desc, min(weight, 5),
               evidence_samples=[match.group(0)], confidence="low",
               rationale="Keyboard handlers are common accessibility and form behavior; correlation is required.",
           )
   long_base64_strings = re.findall(r"[A-Za-z0-9+/]{200,}={0,2}", combined_script)
   if long_base64_strings:
       add_finding(
           result,
           "high",
           "obfuscation",
           "Large base64-like blob found in inline script",
           18,
           evidence_samples=[summarize_long_token(blob) for blob in long_base64_strings[:2]],
           confidence="medium",
       )
   entropy = shannon_entropy(combined_script)
   if len(combined_script) > 500 and entropy > 4.7:
       script_chunks = top_entropy_script_chunks(inline_scripts, max_items=2)
       add_finding(
           result,
           "medium",
           "obfuscation",
           f"High-entropy inline script (entropy={entropy:.2f})",
           6,
           evidence_samples=script_chunks[:2],
           confidence="low",
           rationale="Bundled and minified production JavaScript often has high entropy.",
       )
   minified_lines = [line for line in combined_script.splitlines() if len(line) > 1200]
   if minified_lines:
       add_finding(
           result,
           "low",
           "obfuscation",
           "Very long/minified inline JavaScript lines detected",
           3,
           evidence_samples=[summarize_long_token(line, head=72, tail=32) for line in minified_lines[:2]],
           confidence="low",
       )
   has_password = bool(password_fields)
   has_exfil = any(
       re.search(pat, combined_script, flags=re.I)
       for pat, _, _ in SUSPICIOUS_JS_PATTERNS
       if "fetch" in pat or "XMLHttpRequest" in pat or "sendBeacon" in pat or "Image" in pat or "WebSocket" in pat
   )
   if has_password and has_exfil:
       add_finding(
           result, "high", "correlation", "Credential collection plus client-side transfer behavior", 20,
           confidence="high",
           rationale="A credential form and outbound JavaScript transfer behavior were both observed.",
       )
   if keylog_hits >= 2:
       add_finding(
           result,
           "high",
           "correlation",
           "Multiple keyboard-capture patterns detected",
           20,
           evidence_samples=keylog_samples[:2],
           confidence="medium" if not has_password else "high",
           rationale="Multiple keyboard handlers are stronger only when paired with credential collection.",
       )

JS_INSTRUMENTATION = r"""
(() => {
 if (window.__qrAnalyzerInstalled) return;
 window.__qrAnalyzerInstalled = true;
 window.__qrAnalyzerLog = {
   listenerEvents: [],
   storageEvents: [],
   dynamicScripts: [],
   dynamicIframes: [],
   suspiciousRuntimeHits: [],
   urlChanges: [location.href]
 };
 function pushLimited(arr, value, maxItems = 500) {
   try {
     if (arr.length < maxItems) arr.push(String(value));
   } catch (e) {}
 }
 function runtimeHit(msg) {
   pushLimited(window.__qrAnalyzerLog.suspiciousRuntimeHits, msg, 500);
 }
 const suspiciousEventNames = new Set([
   "keydown", "keypress", "keyup", "input", "paste", "beforeinput"
 ]);
 const originalAddEventListener = EventTarget.prototype.addEventListener;
 EventTarget.prototype.addEventListener = function(type, listener, options) {
   try {
     if (suspiciousEventNames.has(String(type).toLowerCase())) {
       const targetName =
         this === window ? "window" :
         this === document ? "document" :
         (this && this.tagName ? this.tagName.toLowerCase() : Object.prototype.toString.call(this));
       pushLimited(
         window.__qrAnalyzerLog.listenerEvents,
         `${targetName} addEventListener(${String(type)})`
       );
     }
   } catch (e) {}
   return originalAddEventListener.call(this, type, listener, options);
 };
 function wrapStorage(storageObj, storageName) {
   if (!storageObj) return;
   const originalSetItem = storageObj.setItem;
   storageObj.setItem = function(key, value) {
     try {
       const preview = String(value).slice(0, 120);
       pushLimited(
         window.__qrAnalyzerLog.storageEvents,
         `${storageName}.setItem(${String(key)}=${preview})`
       );
     } catch (e) {}
     return originalSetItem.call(this, key, value);
   };
 }
 try { wrapStorage(window.localStorage, "localStorage"); } catch (e) {}
 try { wrapStorage(window.sessionStorage, "sessionStorage"); } catch (e) {}
 const originalEval = window.eval;
 window.eval = function(code) {
   try { runtimeHit(`eval called length=${String(code).length}`); } catch (e) {}
   return originalEval.call(this, code);
 };
 const OriginalFunction = window.Function;
 window.Function = function(...args) {
   try { runtimeHit(`Function constructor used args=${args.length}`); } catch (e) {}
   return OriginalFunction.apply(this, args);
 };
 window.Function.prototype = OriginalFunction.prototype;
 const originalWrite = Document.prototype.write;
 Document.prototype.write = function(...args) {
   try { runtimeHit(`document.write called args=${args.length}`); } catch (e) {}
   return originalWrite.apply(this, args);
 };
 if (navigator.sendBeacon) {
   const originalSendBeacon = navigator.sendBeacon.bind(navigator);
   navigator.sendBeacon = function(url, data) {
     try { runtimeHit(`sendBeacon -> ${String(url)}`); } catch (e) {}
     return originalSendBeacon(url, data);
   };
 }
 const originalAppendChild = Node.prototype.appendChild;
 Node.prototype.appendChild = function(node) {
   try {
     if (node && node.tagName) {
       const tag = node.tagName.toLowerCase();
       if (tag === "script") pushLimited(window.__qrAnalyzerLog.dynamicScripts, node.src || "[inline script appended]");
       else if (tag === "iframe") pushLimited(window.__qrAnalyzerLog.dynamicIframes, node.src || "[iframe appended without src]");
     }
   } catch (e) {}
   return originalAppendChild.call(this, node);
 };
 const originalInsertBefore = Node.prototype.insertBefore;
 Node.prototype.insertBefore = function(node, refNode) {
   try {
     if (node && node.tagName) {
       const tag = node.tagName.toLowerCase();
       if (tag === "script") pushLimited(window.__qrAnalyzerLog.dynamicScripts, node.src || "[inline script inserted]");
       else if (tag === "iframe") pushLimited(window.__qrAnalyzerLog.dynamicIframes, node.src || "[iframe inserted without src]");
     }
   } catch (e) {}
   return originalInsertBefore.call(this, node, refNode);
 };
 const observer = new MutationObserver((mutations) => {
   try {
     for (const m of mutations) {
       for (const node of m.addedNodes || []) {
         if (!node || !node.tagName) continue;
         const tag = node.tagName.toLowerCase();
         if (tag === "script") pushLimited(window.__qrAnalyzerLog.dynamicScripts, node.src || "[inline script mutation]");
         else if (tag === "iframe") pushLimited(window.__qrAnalyzerLog.dynamicIframes, node.src || "[iframe mutation without src]");
       }
     }
   } catch (e) {}
 });
 try {
   observer.observe(document.documentElement || document, { childList: true, subtree: true });
 } catch (e) {}
 try {
   setInterval(() => {
     try {
       const href = location.href;
       const arr = window.__qrAnalyzerLog.urlChanges;
       if (arr[arr.length - 1] !== href) pushLimited(arr, href, 200);
     } catch (e) {}
   }, 500);
 } catch (e) {}
})();
"""

def analyze_browser_behavior(result: AnalysisResult, telemetry: BrowserTelemetry) -> None:
   if telemetry.initial_url and telemetry.final_url and domain_mismatch(telemetry.initial_url, telemetry.final_url):
       add_finding(
           result, "medium", "browser", "Browser final URL differs from initial URL", 10,
           confidence="medium", rationale="Cross-domain redirects are common but relevant when paired with credential or obfuscation signals.",
       )
   if len(telemetry.document_url_changes) >= 3:
       add_finding(result, "medium", "browser", f"Multiple runtime URL changes observed ({len(telemetry.document_url_changes)})", 10)
   cross_domain_requests = 0
   script_requests = 0
   xhr_like = 0
   for req in telemetry.requests:
       if req.resource_type == "script":
           script_requests += 1
       if req.resource_type in {"xhr", "fetch", "beacon"}:
           xhr_like += 1
       if (req.from_domain and req.to_domain and req.from_domain != req.to_domain
               and not is_common_web_service(req.to_domain)):
           cross_domain_requests += 1
   if cross_domain_requests >= 5:
       add_finding(result, "low", "network", f"High number of uncommon cross-domain requests ({cross_domain_requests})", 5, confidence="low")
   if script_requests >= 8:
       add_finding(result, "low", "network", f"Large number of script requests ({script_requests})", 4)
   if xhr_like >= 5:
       add_finding(result, "low", "network", f"High number of active client-side requests ({xhr_like})", 4)
   if telemetry.dynamic_scripts:
       add_finding(
           result,
           "medium",
           "runtime",
           f"Dynamically injected scripts observed ({len(telemetry.dynamic_scripts)})",
           5,
           evidence_samples=telemetry.dynamic_scripts[:2],
           confidence="low",
           rationale="Dynamic script insertion is normal in many web frameworks and tag managers.",
       )
   if telemetry.dynamic_iframes:
       add_finding(
           result,
           "medium",
           "runtime",
           f"Dynamically injected iframes observed ({len(telemetry.dynamic_iframes)})",
           7,
           evidence_samples=telemetry.dynamic_iframes[:2],
           confidence="medium",
       )
   suspicious_listener_hits = [
       x for x in telemetry.listener_events
       if any(k in x.lower() for k in ["keydown", "keypress", "keyup", "paste", "input", "beforeinput"])
   ]
   if len(suspicious_listener_hits) >= 2:
       add_finding(
           result,
           "low",
           "runtime",
           f"Multiple keyboard/input listener registrations observed ({len(suspicious_listener_hits)})",
           5,
           evidence_samples=suspicious_listener_hits[:2],
           confidence="low",
           rationale="Input listeners are common; they are escalated only when correlated with credential collection and transfer behavior.",
       )
   if telemetry.storage_events:
       add_finding(
           result,
           "low",
           "storage",
           f"Page wrote to browser storage ({len(telemetry.storage_events)} events)",
           4,
           evidence_samples=telemetry.storage_events[:2],
       )
   for hit in telemetry.suspicious_runtime_hits:
       low = hit.lower()
       evidence = runtime_hit_evidence_from_html(telemetry.html, hit) or [hit]
       if "eval" in low:
           add_finding(result, "medium", "runtime-js", hit, 12, evidence_samples=evidence, confidence="medium")
       elif "function constructor" in low:
           add_finding(result, "medium", "runtime-js", hit, 12, evidence_samples=evidence, confidence="medium")
       elif "sendbeacon" in low:
           add_finding(result, "low", "runtime-js", hit, 5, evidence_samples=evidence, confidence="low")
       elif "document.write" in low:
           add_finding(result, "low", "runtime-js", hit, 3, evidence_samples=evidence, confidence="low")
   if len(telemetry.failed_requests) >= 5:
       add_finding(result, "low", "network", f"Many failed network requests observed ({len(telemetry.failed_requests)})", 4)
   if telemetry.page_title:
       title = telemetry.page_title.lower()
       if any(word in title for word in ["login", "verify", "account", "wallet", "secure", "password"]):
           add_finding(result, "low", "content", f"Sensitive/login-oriented page title: {telemetry.page_title}", 5)
   credential_form = any("password" in form.input_types for form in result.forms)
   external_form = any(form.external_action for form in result.forms)
   outbound_activity = any(
       req.resource_type in {"xhr", "fetch", "beacon"}
       and req.to_domain
       and domain_mismatch(telemetry.final_url or telemetry.initial_url, req.url)
       and not is_common_web_service(req.to_domain)
       for req in telemetry.requests
   )
   if credential_form and suspicious_listener_hits and (external_form or outbound_activity):
       add_finding(
           result, "critical", "correlation",
           "Credential form, input capture, and external transfer behavior observed together",
           35, evidence_samples=suspicious_listener_hits[:2], confidence="high",
           rationale="Three separate warning signs point to a possible credential-stealing page.",
       )

def run_browser_analysis(url: str, wait_ms: int = 7000, screenshot_path: str = "") -> BrowserTelemetry:
   require_public_network_target(url)
   try:
       from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
       from playwright.sync_api import sync_playwright
   except ModuleNotFoundError as exc:
       raise RuntimeError(
           "Playwright is not installed. Install it with 'pip install playwright' "
           "and then run 'playwright install chromium'."
       ) from exc
   telemetry = BrowserTelemetry(initial_url=url)
   with sync_playwright() as p:
       browser = p.chromium.launch(
           headless=True,
           args=[
               "--disable-dev-shm-usage",
               "--disable-blink-features=AutomationControlled",
               "--disable-webrtc",
           ],
       )
       context = browser.new_context(
           java_script_enabled=True,
           ignore_https_errors=False,
            viewport={"width": 1440, "height": 1800},
            accept_downloads=False,
            service_workers="block",
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        )
       target_cache: Dict[str, bool] = {}
       def guard_request(route) -> None:
           request_url = route.request.url
           parsed = urlparse(request_url)
           if parsed.scheme not in {"http", "https"}:
               route.abort()
               return
           origin = f"{parsed.scheme}://{parsed.netloc}"
           allowed = target_cache.get(origin)
           if allowed is None:
               allowed, _, _ = classify_network_target(request_url)
               target_cache[origin] = allowed
           if allowed:
               route.continue_()
           else:
               route.abort()
       context.route("**/*", guard_request)
       page = context.new_page()
       page.add_init_script(JS_INSTRUMENTATION)
       def on_console(msg) -> None:
           try:
               text = msg.text
           except Exception:
               text = "<unreadable console message>"
           if len(telemetry.console_messages) < 300:
               telemetry.console_messages.append(text)
       def on_request(req) -> None:
           from_domain = get_domain(page.url) if page.url else ""
           to_domain = get_domain(req.url)
           telemetry.requests.append(
               NetworkRecord(
                   method=req.method,
                   url=req.url,
                   resource_type=req.resource_type,
                   from_domain=from_domain,
                   to_domain=to_domain,
               )
           )
       def on_response(resp) -> None:
           try:
               req = resp.request
               for rec in reversed(telemetry.requests):
                   if rec.url == req.url and rec.method == req.method and rec.status is None:
                       rec.status = resp.status
                       break
           except Exception:
               pass
       def on_request_failed(req) -> None:
           telemetry.failed_requests.append(req.url)
       page.on("console", on_console)
       page.on("request", on_request)
       page.on("response", on_response)
       page.on("requestfailed", on_request_failed)
       try:
           page.goto(url, wait_until="domcontentloaded", timeout=15000)
           page.wait_for_timeout(wait_ms)
       except PlaywrightTimeoutError:
           pass
       try:
           page.wait_for_load_state("networkidle", timeout=5000)
       except Exception:
           pass
       telemetry.final_url = page.url
       try:
           telemetry.page_title = page.title()
       except Exception:
           telemetry.page_title = ""
       if screenshot_path:
           try:
               page.screenshot(path=screenshot_path, full_page=True)
               telemetry.screenshot_path = screenshot_path
           except Exception:
               telemetry.screenshot_path = ""
       try:
           log_data = page.evaluate("""
               () => window.__qrAnalyzerLog || {
                   listenerEvents: [],
                   storageEvents: [],
                   dynamicScripts: [],
                   dynamicIframes: [],
                   suspiciousRuntimeHits: [],
                   urlChanges: [location.href]
               }
           """)
       except Exception:
           log_data = {
               "listenerEvents": [],
               "storageEvents": [],
               "dynamicScripts": [],
               "dynamicIframes": [],
               "suspiciousRuntimeHits": [],
               "urlChanges": [page.url],
           }
       telemetry.listener_events = list(log_data.get("listenerEvents", []))
       telemetry.storage_events = list(log_data.get("storageEvents", []))
       telemetry.dynamic_scripts = list(log_data.get("dynamicScripts", []))
       telemetry.dynamic_iframes = list(log_data.get("dynamicIframes", []))
       telemetry.suspicious_runtime_hits = list(log_data.get("suspiciousRuntimeHits", []))
       telemetry.document_url_changes = list(log_data.get("urlChanges", []))
       try:
           telemetry.html = page.content()
       except Exception:
           telemetry.html = ""
       context.close()
       browser.close()
   return telemetry

def dedupe_findings(findings: List[Finding]) -> List[Finding]:
   merged: Dict[tuple[str, str, str, int], Finding] = {}
   for f in findings:
       key = (f.severity, f.category, f.message, f.weight)
       if key not in merged:
            merged[key] = Finding(
                severity=f.severity,
                category=f.category,
                message=f.message,
                weight=f.weight,
                evidence_samples=list(f.evidence_samples),
                confidence=f.confidence,
                finding_id=f.finding_id,
                rationale=f.rationale,
            )
       else:
           merged[key].evidence_samples = merge_evidence(
               merged[key].evidence_samples,
               f.evidence_samples,
           )
   return list(merged.values())

def dedupe_forms(forms: List[FormRecord]) -> List[FormRecord]:
   seen = set()
   out: List[FormRecord] = []
   for form in forms:
       key = (
           form.action,
           form.method,
           tuple(form.input_types),
           tuple(form.input_names),
           form.external_action,
       )
       if key not in seen:
           seen.add(key)
           out.append(form)
   return out

def analyze_qr_target(
   image_path: str,
   browser_wait_ms: int = 7000,
   screenshot_path: str = "",
   analysis_mode: str = "offline",
) -> AnalysisResult:
   result = AnalysisResult(
       analysis_mode=analysis_mode,
       image_sha256=file_sha256(image_path),
       started_at=datetime.now(timezone.utc).isoformat(),
   )
   qr_value = decode_qr_image(image_path)
   result.qr_value = qr_value
   if not is_http_url(qr_value):
       result.initial_url = qr_value
       add_finding(result, "high", "qr", "QR content is not a valid HTTP/HTTPS URL", 25)
       result.completed_at = datetime.now(timezone.utc).isoformat()
       return result
   result.initial_url = qr_value
   analyze_url_structure(result, qr_value)
   if analysis_mode == "offline":
       result.notes.append("Network access was disabled; no destination was contacted.")
       result.findings = dedupe_findings(result.findings)
       result.completed_at = datetime.now(timezone.utc).isoformat()
       return result
   network_target_allowed = True
   try:
       response, html_from_requests = safe_get(qr_value)
       result.http_status = response.status_code
       result.final_url = response.url
       result.redirects = [r.url for r in response.history] + [response.url]
       analyze_url_structure(result, response.url)
       analyze_redirects(result)
       analyze_html(result, html_from_requests, response.url)
   except ValueError as exc:
       network_target_allowed = False
       result.notes.append(str(exc))
       add_finding(
           result, "high", "network", str(exc), 20, confidence="high",
           rationale="Network-enabled analysis refuses destinations that may reach local or reserved address space.",
       )
   except requests.exceptions.SSLError:
       add_finding(result, "high", "network", "TLS/SSL error while connecting", 20)
   except requests.exceptions.TooManyRedirects:
       add_finding(result, "high", "network", "Too many redirects", 20)
   except requests.exceptions.Timeout:
       add_finding(result, "medium", "network", "Static fetch timed out", 10)
   except requests.exceptions.RequestException as exc:
       add_finding(result, "medium", "network", f"HTTP error during static fetch: {exc}", 10)
   except Exception as exc:
       add_finding(result, "medium", "runtime", f"Unexpected static analysis error: {exc}", 10)
   if analysis_mode == "browser" and network_target_allowed:
       try:
           browser_telemetry = run_browser_analysis(qr_value, wait_ms=browser_wait_ms, screenshot_path=screenshot_path)
           result.browser = browser_telemetry
           if browser_telemetry.final_url:
               result.final_url = browser_telemetry.final_url
           if browser_telemetry.document_url_changes:
               result.redirects = browser_telemetry.document_url_changes
           analyze_browser_behavior(result, browser_telemetry)
           if browser_telemetry.html:
               analyze_html(
                   result,
                   browser_telemetry.html,
                   browser_telemetry.final_url or result.final_url or qr_value,
               )
       except Exception as exc:
           add_finding(result, "medium", "browser", f"Headless browser analysis failed: {exc}", 8, confidence="medium")
   elif analysis_mode != "browser":
       result.notes.append("Browser execution was disabled; runtime behavior was not observed.")
   result.forms = dedupe_forms(result.forms)
   result.script_urls = dedupe_preserve(result.script_urls)
   result.findings = dedupe_findings(result.findings)
   result.completed_at = datetime.now(timezone.utc).isoformat()
   return result

def result_to_jsonable(result: AnalysisResult) -> Dict[str, Any]:
   severity_counts = dict(Counter(f.severity for f in result.findings))
   confidence_counts = dict(Counter(f.confidence for f in result.findings))
   category_counts = dict(Counter(f.category for f in result.findings))
   key_findings = sorted(
       result.findings,
       key=lambda finding: (
           {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(finding.severity, 0),
           {"high": 3, "medium": 2, "low": 1}.get(finding.confidence, 0),
           finding.weight,
       ),
       reverse=True,
   )[:5]
   return {
       "schema_version": "2.0",
       "report": {
           "generated_at": result.completed_at,
           "analysis_mode": result.analysis_mode,
           "engine": "QR Vamp",
       },
       "executive_summary": {
           "verdict": result.verdict,
           "risk_score": result.score,
           "confidence": result.confidence,
           "key_findings": [asdict(finding) for finding in key_findings],
           "finding_counts": {
               "total": len(result.findings),
               "by_severity": severity_counts,
               "by_confidence": confidence_counts,
               "by_category": category_counts,
           },
           "limitations": result.notes,
       },
       "evidence": {
           "image_sha256": result.image_sha256,
           "qr_value": result.qr_value,
       },
       "target": {
           "initial_url": result.initial_url,
           "final_url": result.final_url,
           "http_status": result.http_status,
           "redirect_chain": result.redirects,
       },
       "findings": [asdict(finding) for finding in result.findings],
       "artifacts": {
           "forms": [asdict(form) for form in result.forms],
           "script_urls": result.script_urls,
           "browser": asdict(result.browser) if result.browser else None,
       },
       "timing": {
           "started_at": result.started_at,
           "completed_at": result.completed_at,
       },
   }

def write_network_csv(path: str, records: List[NetworkRecord]) -> None:
   with open(path, "w", newline="", encoding="utf-8") as f:
       writer = csv.writer(f)
       writer.writerow(["method", "url", "resource_type", "status", "from_domain", "to_domain"])
       for r in records:
           writer.writerow([r.method, r.url, r.resource_type, r.status, r.from_domain, r.to_domain])

def write_lines(path: str, lines: List[str]) -> None:
   with open(path, "w", encoding="utf-8") as f:
       for line in lines:
           f.write(line + "\n")

def print_report(result: AnalysisResult) -> None:
   width = 96
   line = colorize("=" * width, Color.RED)
   severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
   confidence_rank = {"high": 3, "medium": 2, "low": 1}
   ordered = sorted(
       result.findings,
       key=lambda finding: (
           severity_rank.get(finding.severity, 0),
           confidence_rank.get(finding.confidence, 0),
           finding.weight,
       ),
       reverse=True,
   )
   counts = Counter(f.severity for f in result.findings)

   print(line)
   print(colorize("QR VAMP ANALYSIS REPORT", Color.BOLD, Color.WHITE))
   print(line)
   print(colorize("SUMMARY", Color.BOLD, Color.WHITE))
   print(f"  Verdict       : {colorize(result.verdict, Color.BOLD, verdict_color(result.verdict))}")
   print(f"  Risk score    : {result.score}/100")
   print(f"  Confidence    : {result.confidence.upper()}")
   print(f"  Analysis mode : {result.analysis_mode.upper()}")
   print(f"  Findings      : {len(result.findings)} "
         f"(critical={counts.get('critical', 0)}, high={counts.get('high', 0)}, "
         f"medium={counts.get('medium', 0)}, low={counts.get('low', 0)})")

   print(colorize("\nEVIDENCE AND SCOPE", Color.BOLD, Color.WHITE))
   print(f"  Image SHA-256 : {result.image_sha256}")
   print(f"  QR value      : {result.qr_value}")
   print(f"  Initial URL   : {result.initial_url or 'N/A'}")
   print(f"  Final URL     : {result.final_url or 'Not contacted'}")
   print(f"  HTTP status   : {result.http_status if result.http_status is not None else 'N/A'}")
   for note in result.notes:
       print(f"  Limitation    : {note}")

   print(colorize("\nPRIORITY FINDINGS", Color.BOLD, Color.WHITE))
   if not ordered:
       print(colorize("  No suspicious indicators were identified in the completed scope.", Color.GREEN))
   for finding in ordered:
       sev = colorize(finding.severity.upper(), Color.BOLD, severity_color(finding.severity))
       print(f"  [{finding.finding_id}] {sev} | confidence={finding.confidence.upper()} | {finding.category}")
       print(f"    {finding.message}")
       if finding.rationale:
           print(f"    Why it matters: {finding.rationale}")
       for sample in finding.evidence_samples[:2]:
           print(f"    Evidence: {sample}")

   print(colorize("\nOBSERVED ARTIFACTS", Color.BOLD, Color.WHITE))
   print(f"  Redirects     : {len(result.redirects)}")
   for index, url in enumerate(result.redirects[:10], 1):
       print(f"    {index}. {url}")
   print(f"  Forms         : {len(result.forms)}")
   for index, form in enumerate(result.forms[:10], 1):
       print(f"    {index}. {form.method} {form.action} external={form.external_action}")
   print(f"  Script URLs   : {len(result.script_urls)}")
   if result.browser:
       print(f"  Requests      : {len(result.browser.requests)}")
       print(f"  Failed        : {len(result.browser.failed_requests)}")
       print(f"  Dynamic code  : {len(result.browser.dynamic_scripts)} scripts, "
             f"{len(result.browser.dynamic_iframes)} iframes")
       print(f"  Browser state : {len(result.browser.storage_events)} storage writes, "
             f"{len(result.browser.listener_events)} input listeners")
       print(f"  Screenshot    : {result.browser.screenshot_path or 'Not requested'}")
   print(line)

def _legacy_print_banner():
    owl_art = colorize(
        """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣶⣶⣶⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢦⣤⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣤⣤⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⠟⠁⢀⣈⠙⢿⣿⣿⣿⠟⠁⢀⣈⠙⢿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠀⢻⣿⡿⠂⣸⣿⣿⣿⠀⢻⣿⡿⠀⣸⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣷⣤⣄⣤⣴⣿⠁⠀⣻⣷⣤⣄⣤⣴⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣧⢠⣿⣿⣿⣿⣿⣿⣿⣿⣝⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⠟⣭⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣻⣻⣿⣿⠇⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠿⢟⠿⢿⣿⡄⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⡿⢿⣿⣿⣷⡈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣾⣷⣾⣿⣿⣷⣄⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣮⣶⣭⣭⣛⣽⣿⣿⣦⣈⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⣭⣯⣻⣝⣛⣿⣿⣿⣿⣶⣤⣉⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀
⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣛⣛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣉⡛⠿⣿⣿⣿⣿⣿⣿⣇⠀
⠀⠀⠀⠀⠈⠙⠷⣶⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣯⣽⣿⣿⣿⣿⡄
⠀⠀⠀⠀⠀⠰⣄⠀⣀⠉⠉⠛⠛⠷⠶⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠙⢿⣧
⠀⠀⠀⠘⠛⠓⢉⡄⡹⠆⠀⠀⠀⠀⠀⠉⠛⠿⢷⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⡏⠛⠛⠛⠛⠛⠊⢿⣿⣿⠀⠀⠙
⠀⠀⠀⠀⠀⠀⠉⠛⠋⠢⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣷⣦⣄⣀⡀⠀⠀⢀⣀⣼⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠈⢻⣿⡀⠀⠀
⠈⠉⠙⠒⠲⠶⠶⢶⣶⣤⣬⣽⣶⣦⣤⣤⣤⣶⣶⣿⡿⠿⠿⠟⠛⠿⠿⠏⣴⣿⣿⠟⣛⣛⣋⣀⣀⡀⠀⠀⡀⠀⠀⠀⠀⠹⡇⠀⠀
⠀⠀⠀⠀⢀⣠⠶⠛⠋⠉⠉⠁⠀⠈⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠈⢏⠈⡏⠈⠛⠛⠻⠿⢿⣿⣿⣿⣿⣿⣶⣦⣤⣤⠑⠀⠀
⠀⠀⠀⠐⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠻⠿⣿⡇⠀⠀⠀
""".strip("\n"),
        Color.BLUE,
    )
    banner = rf"""
{owl_art}

  ██████  ██████        ██████  ██     ██ ██
 ██    ██ ██   ██      ██    ██ ██     ██ ██
 ██    ██ ██████       ██    ██ ██  █  ██ ██
 ██ ▄▄ ██ ██   ██      ██    ██ ██ ███ ██ ██
  ██████  ██   ██       ██████   ███ ███  ███████
     ▀▀

                QR Vamp
        Defensive QR Code Security Analysis
                  nullvamp
    """
    print(colorize(banner, Color.MAGENTA))

def print_banner() -> None:
   print(colorize(TERMINAL_LOGO, Color.RED))
   print()
   print(colorize("QR Vamp", Color.BOLD, Color.WHITE))
   print(colorize("Defensive QR Code Security Analysis", Color.WHITE))

def print_section(title: str) -> None:
   line = colorize("=" * 88, Color.RED)
   print(f"\n{line}")
   print(colorize(title, Color.BOLD, Color.WHITE))
   print(line)

def print_step(label: str, message: str) -> None:
   print(f"[{colorize(label, Color.BOLD, Color.GREEN)}] {message}")

def prompt_text(prompt: str, default: str = "", allow_empty: bool = True) -> str:
   suffix = f" [{default}]" if default else ""
   while True:
       value = input(f"{prompt}{suffix}: ").strip()
       if value:
           return value
       if default:
           return default
       if allow_empty:
           return ""
       print("Input is required.")

def normalize_user_path(value: str) -> str:
   value = value.strip()
   if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
       return value[1:-1]
   return value

def prompt_path(label: str, default: str = "", allow_empty: bool = True) -> str:
   try:
       from prompt_toolkit import prompt as rich_prompt
       from prompt_toolkit.completion import PathCompleter
   except ModuleNotFoundError:
       return normalize_user_path(prompt_text(label, default=default, allow_empty=allow_empty))
   while True:
       value = rich_prompt(
           f"{label}: ",
           default=default,
           completer=PathCompleter(expanduser=True),
           complete_while_typing=False,
       )
       value = normalize_user_path(value)
       if value or allow_empty:
           return value
       print("Input is required.")

def prompt_int(prompt: str, default: int) -> int:
   while True:
       raw = input(f"{prompt} [{default}]: ").strip()
       if not raw:
           return default
       try:
           value = int(raw)
           if value < 0:
               raise ValueError
           return value
       except ValueError:
           print("Enter a valid non-negative integer.")

def prompt_yes_no(prompt: str, default: bool = True) -> bool:
   default_hint = "Y/n" if default else "y/N"
   while True:
       raw = input(f"{prompt} [{default_hint}]: ").strip().lower()
       if not raw:
           return default
       if raw in {"y", "yes"}:
           return True
       if raw in {"n", "no"}:
           return False
       print("Enter y or n.")

def normalize_optional_path(value: Optional[str]) -> str:
   return (value or "").strip()

def derive_output_paths(image_path: str, output_dir: str = "") -> Dict[str, str]:
   abs_image = os.path.abspath(image_path)
   base_name = os.path.splitext(os.path.basename(abs_image))[0]
   base_dir = os.path.abspath(output_dir or os.path.join(os.getcwd(), "output", base_name))
   return {
       "json": os.path.join(base_dir, f"{base_name}_analysis.json"),
       "html": os.path.join(base_dir, f"{base_name}_report.html"),
       "csv": os.path.join(base_dir, f"{base_name}_network.csv"),
       "scripts": os.path.join(base_dir, f"{base_name}_scripts.txt"),
       "screenshot": os.path.join(base_dir, f"{base_name}_screenshot.png"),
   }

def build_arg_parser() -> argparse.ArgumentParser:
   parser = argparse.ArgumentParser(
       description="Analyze the landing page behind a QR code image."
   )
   parser.add_argument("image", nargs="?", help="Path to the QR image file.")
   parser.add_argument(
       "--mode",
       choices=["offline", "static", "browser"],
       default="offline",
       help="Analysis depth. Offline is the safe default; static and browser contact the destination.",
   )
   parser.add_argument(
       "--output-dir",
       dest="output_dir",
       default="",
       help="Directory for generated reports. Defaults to ./output/<image-name>.",
   )
   parser.add_argument("--json-out", dest="json_out", help="Path to write the JSON report.")
   parser.add_argument("--html-out", dest="html_out", help="Path to write a self-contained HTML report.")
   parser.add_argument("--csv-out", dest="csv_out", help="Path to write the network CSV.")
   parser.add_argument("--scripts-out", dest="scripts_out", help="Path to write discovered script URLs.")
   parser.add_argument("--screenshot", dest="screenshot", help="Path to save a browser screenshot.")
   parser.add_argument(
       "--browser-wait-ms",
       dest="browser_wait_ms",
       type=int,
       default=7000,
       help="How long to wait for runtime behavior after page load.",
   )
   parser.add_argument(
       "--non-interactive",
       action="store_true",
       help="Run only from arguments and skip the interactive wizard.",
   )
   return parser

def gather_interactive_config(args: argparse.Namespace) -> argparse.Namespace:
   print_section("QR Vamp is Ready")
   print("Leave optional outputs blank to skip them.")

   image_path = args.image or ""
   while True:
       image_path = prompt_path("QR image path", default=image_path, allow_empty=False)
       if os.path.isfile(image_path):
           break
       print("File not found. Enter a valid image path.")

   while True:
       mode = prompt_text("Analysis mode (offline/static/browser)", default=args.mode or "offline", allow_empty=False).lower()
       if mode in {"offline", "static", "browser"}:
           break
       print("Choose offline, static, or browser.")
   if mode != "offline":
       print(colorize("Warning: this mode contacts the QR destination. Use an isolated analysis VM.", Color.RED, Color.BOLD))
       if not prompt_yes_no("Continue with network access?", default=False):
           mode = "offline"
   args.mode = mode
   args.output_dir = prompt_path(
       "Output directory",
       default=args.output_dir or os.path.join(os.getcwd(), "output", os.path.splitext(os.path.basename(image_path))[0]),
       allow_empty=False,
   )
   suggested = derive_output_paths(image_path, args.output_dir)
   save_json = prompt_yes_no("Write a JSON report?", default=bool(args.json_out) or True)
   save_html = prompt_yes_no("Write an HTML report?", default=bool(args.html_out) or True)
   save_csv = prompt_yes_no("Write a network CSV?", default=bool(args.csv_out))
   save_scripts = prompt_yes_no("Write a script URL list?", default=bool(args.scripts_out))
   save_screenshot = mode == "browser" and prompt_yes_no("Save a browser screenshot?", default=bool(args.screenshot))

   args.image = image_path
   args.json_out = prompt_path("JSON output path", default=args.json_out or suggested["json"]) if save_json else ""
   args.html_out = prompt_path("HTML output path", default=args.html_out or suggested["html"]) if save_html else ""
   args.csv_out = prompt_path("CSV output path", default=args.csv_out or suggested["csv"]) if save_csv else ""
   args.scripts_out = prompt_path("Scripts output path", default=args.scripts_out or suggested["scripts"]) if save_scripts else ""
   args.screenshot = prompt_path("Screenshot path", default=args.screenshot or suggested["screenshot"]) if save_screenshot else ""
   args.browser_wait_ms = prompt_int("Browser wait time in ms", args.browser_wait_ms)
   return args

def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
   if args.browser_wait_ms < 0:
       parser.error("--browser-wait-ms must be non-negative.")
   if not args.image:
       parser.error("an image path is required.")
   if not os.path.isfile(args.image):
       parser.error(f"image file not found: {args.image}")
   if args.screenshot and args.mode != "browser":
       parser.error("--screenshot requires --mode browser")

def write_html_report(path: str, result: AnalysisResult) -> None:
   esc = lambda value: html_lib.escape(str(value), quote=True)
   severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
   ordered = sorted(result.findings, key=lambda finding: (severity_rank.get(finding.severity, 0), finding.weight), reverse=True)
   finding_cards = []
   for finding in ordered:
       evidence = "".join(f"<li><code>{esc(sample)}</code></li>" for sample in finding.evidence_samples[:2])
       rationale = f"<p class='rationale'>{esc(finding.rationale)}</p>" if finding.rationale else ""
       finding_cards.append(
           f"<article class='finding {esc(finding.severity)}'>"
           f"<div class='finding-head'><span class='id'>{esc(finding.finding_id)}</span>"
           f"<span class='badge'>{esc(finding.severity.upper())}</span>"
           f"<span class='confidence'>{esc(finding.confidence.upper())} CONFIDENCE</span></div>"
           f"<h3>{esc(finding.message)}</h3><p class='category'>{esc(finding.category)}</p>"
           f"{rationale}<ul>{evidence}</ul></article>"
       )
   if not finding_cards:
       finding_cards.append("<div class='empty'>No suspicious indicators were identified in the completed scope.</div>")
   redirects = "".join(f"<li><code>{esc(url)}</code></li>" for url in result.redirects) or "<li>None observed</li>"
   limitations = "".join(f"<li>{esc(note)}</li>" for note in result.notes) or "<li>None recorded</li>"
   browser_metrics = ""
   if result.browser:
       browser_metrics = (
           f"<div class='metric'><span>Requests</span><strong>{len(result.browser.requests)}</strong></div>"
           f"<div class='metric'><span>Failed</span><strong>{len(result.browser.failed_requests)}</strong></div>"
           f"<div class='metric'><span>Dynamic scripts</span><strong>{len(result.browser.dynamic_scripts)}</strong></div>"
           f"<div class='metric'><span>Input listeners</span><strong>{len(result.browser.listener_events)}</strong></div>"
       )
   verdict_class = "danger" if result.verdict == "HIGH RISK" else "warn" if result.verdict == "SUSPICIOUS" else "safe"
   document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QR Vamp Report - {esc(result.verdict)}</title>
<style>
:root{{--bg:#071018;--panel:#0d1822;--line:#203241;--text:#dce8f2;--muted:#87a0b5;--cyan:#38bdf8;--red:#fb7185;--amber:#fbbf24;--green:#34d399}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,Segoe UI,Arial,sans-serif}}
main{{max-width:1120px;margin:auto;padding:42px 24px 80px}}header{{display:flex;justify-content:space-between;gap:24px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:24px}}
h1{{margin:0;font-size:34px;letter-spacing:-1px}}h2{{font-size:13px;color:var(--cyan);text-transform:uppercase;letter-spacing:1.6px;margin:34px 0 14px}}h3{{font-size:16px;margin:12px 0 2px}}
.sub,.muted,.category,.rationale{{color:var(--muted)}}.verdict{{font-size:17px;font-weight:800;padding:10px 14px;border:1px solid;border-radius:6px}}.danger{{color:var(--red)}}.warn{{color:var(--amber)}}.safe{{color:var(--green)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}}.metric,.panel,.finding{{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:16px}}.metric span{{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}}.metric strong{{font-size:24px;color:var(--cyan)}}
.panel dl{{display:grid;grid-template-columns:140px 1fr;gap:10px;margin:0}}dt{{color:var(--muted)}}dd{{margin:0;overflow-wrap:anywhere}}code{{color:#b9ddf5;overflow-wrap:anywhere}}.findings{{display:grid;gap:10px}}.finding{{border-left:3px solid var(--line)}}.finding.critical,.finding.high{{border-left-color:var(--red)}}.finding.medium{{border-left-color:var(--amber)}}.finding.low{{border-left-color:var(--cyan)}}
.finding-head{{display:flex;gap:8px;align-items:center}}.id,.badge,.confidence{{font-size:10px;letter-spacing:1px}}.badge{{font-weight:800}}.confidence{{color:var(--muted)}}ul{{padding-left:20px}}footer{{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}}
@media(max-width:620px){{header{{align-items:start;flex-direction:column}}.panel dl{{grid-template-columns:1fr}}}}
</style></head><body><main>
<header><div><div class="sub">DEFENSIVE QR CODE ANALYSIS</div><h1>QR Vamp</h1><div class="muted">Generated {esc(result.completed_at or 'N/A')}</div></div><div class="verdict {verdict_class}">{esc(result.verdict)}</div></header>
<h2>Summary</h2><section class="grid"><div class="metric"><span>Risk score</span><strong>{result.score}/100</strong></div><div class="metric"><span>Confidence</span><strong>{esc(result.confidence.upper())}</strong></div><div class="metric"><span>Mode</span><strong>{esc(result.analysis_mode.upper())}</strong></div><div class="metric"><span>Findings</span><strong>{len(result.findings)}</strong></div>{browser_metrics}</section>
<h2>Evidence and target</h2><section class="panel"><dl><dt>Image SHA-256</dt><dd><code>{esc(result.image_sha256)}</code></dd><dt>QR value</dt><dd><code>{esc(result.qr_value)}</code></dd><dt>Initial URL</dt><dd><code>{esc(result.initial_url or 'N/A')}</code></dd><dt>Final URL</dt><dd><code>{esc(result.final_url or 'Not contacted')}</code></dd><dt>HTTP status</dt><dd>{esc(result.http_status if result.http_status is not None else 'N/A')}</dd></dl></section>
<h2>Priority findings</h2><section class="findings">{''.join(finding_cards)}</section>
<h2>Redirect flow</h2><section class="panel"><ol>{redirects}</ol></section>
<h2>Scope limitations</h2><section class="panel"><ul>{limitations}</ul></section>
<footer>Review the findings yourself. Open suspicious links only from an isolated analysis machine.</footer>
</main></body></html>"""
   os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
   with open(path, "w", encoding="utf-8") as handle:
       handle.write(document)

def write_outputs(result: AnalysisResult, json_out: str, html_out: str, csv_out: str, scripts_out: str) -> None:
   if json_out:
       os.makedirs(os.path.dirname(os.path.abspath(json_out)), exist_ok=True)
       with open(json_out, "w", encoding="utf-8") as f:
           json.dump(result_to_jsonable(result), f, indent=2, ensure_ascii=False)
       print_step("SAVE", f"JSON report written to {json_out}")
   if html_out:
       write_html_report(html_out, result)
       print_step("SAVE", f"HTML report written to {html_out}")
   if csv_out and result.browser:
       os.makedirs(os.path.dirname(os.path.abspath(csv_out)), exist_ok=True)
       write_network_csv(csv_out, result.browser.requests)
       print_step("SAVE", f"Network CSV written to {csv_out}")
   if scripts_out:
       os.makedirs(os.path.dirname(os.path.abspath(scripts_out)), exist_ok=True)
       write_lines(scripts_out, result.script_urls)
       print_step("SAVE", f"Script list written to {scripts_out}")

def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    enable_ansi_colors()
    print_banner()
    print()

    try:
        if not args.non_interactive:
            args = gather_interactive_config(args)
        validate_args(args, parser)

        image_path = args.image
        json_out = normalize_optional_path(args.json_out)
        html_out = normalize_optional_path(args.html_out)
        csv_out = normalize_optional_path(args.csv_out)
        scripts_out = normalize_optional_path(args.scripts_out)
        screenshot = normalize_optional_path(args.screenshot)

        print_section("Run Summary")
        print_step("INPUT", f"Image: {os.path.abspath(image_path)}")
        print_step("MODE ", args.mode)
        print_step("WAIT ", f"Browser wait: {args.browser_wait_ms} ms")
        print_step("JSON ", json_out or "Skipped")
        print_step("HTML ", html_out or "Skipped")
        print_step("CSV  ", csv_out or "Skipped")
        print_step("JS   ", scripts_out or "Skipped")
        print_step("SHOT ", screenshot or "Skipped")

        print_section("Analysis In Progress")
        activity = {
            "offline": "Decoding the QR code and evaluating its value without network access.",
            "static": "Decoding the QR code and retrieving static page content.",
            "browser": "Decoding the QR code and recording what the page does in a monitored browser.",
        }[args.mode]
        print(activity + "\n")

        result = analyze_qr_target(
            image_path,
            browser_wait_ms=args.browser_wait_ms,
            screenshot_path=screenshot,
            analysis_mode=args.mode,
        )
        print_report(result)
        write_outputs(result, json_out, html_out, csv_out, scripts_out)
        print_section("Completed")
        print("Analysis complete.")
        if not args.non_interactive:
            input("Press Enter to exit...")
        return 0
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Fatal error: {exc}", file=sys.stderr)
        if not args.non_interactive:
            input("Press Enter to exit...")
        return 1

if __name__ == "__main__":
   raise SystemExit(main())
