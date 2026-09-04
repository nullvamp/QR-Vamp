<p align="center">
  <img src="docs/assets/logo-red.svg" width="160" alt="QR Vamp logo">
</p>

<h1 align="center">QR Vamp</h1>

QR Vamp checks QR codes for suspicious links and page behavior. It can read a QR code without opening the link, download the page HTML, or open the page in a monitored browser that records what it does.

## Safety model

The default `offline` mode never contacts the decoded destination. Network access must be explicitly selected:

- `offline`: decode and inspect the QR value only.
- `static`: retrieve HTML without executing page JavaScript.
- `browser`: open the page in a monitored Chromium browser and record its activity.

Static and browser modes can expose the analyst's IP address and tell the remote server that the link was opened. Use them only from a disposable analysis VM. QR Vamp tries to block local, private, reserved, and other non-public addresses, including redirects. A separate VM is still required because no browser visit can be made completely safe.

## Reports

JSON reports use a versioned structure with:

- A clear summary, verdict, score, and confidence level
- Finding counts by severity, confidence, and category
- Ranked key findings
- Evidence identity using SHA-256
- Target and redirect details
- Full findings with rationale and evidence
- Forms, scripts, and recorded browser activity
- Analysis limitations and timestamps
- A self-contained dark HTML report suitable for local review

Common website behavior such as minified JavaScript, password fields, external scripts, and keyboard listeners receives a low score by itself. QR Vamp reports high risk only when several strong warning signs appear together.

## Installation

Python 3.11 or 3.12 is recommended.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m playwright install chromium
```

## Usage

### Interactive terminal

Run the Python file without arguments:

```powershell
python QR.py
```

This opens QR Vamp's interactive terminal interface. It prompts for the QR image,
analysis mode, and optional report paths. Path prompts support Tab completion for
files and directories, including paths containing spaces.

### Command line

Use command arguments when you want to run an analysis directly or from a script.

Safe offline analysis:

```powershell
python QR.py sample.png --mode offline --non-interactive --json-out output\sample\report.json --html-out output\sample\report.html
```

Static retrieval from an isolated VM:

```powershell
python QR.py sample.png --mode static --non-interactive --json-out output\sample\report.json
```

Monitored browser analysis from an isolated VM:

```powershell
python QR.py sample.png --mode browser --non-interactive --json-out output\sample\report.json --screenshot output\sample\page.png
```

Surrounding quotes around paths are accepted and removed automatically.

## Evidence handling

Keep original QR images read-only. Store reports in a separate output directory. Generated reports may contain sensitive URLs, identifiers, tokens, and page content; review them before sharing.

## Status

QR Vamp provides decision support, not an automatic verdict. Always review its
findings yourself and use an isolated machine when opening suspicious links.
