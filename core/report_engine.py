"""
m7lfi - Report Engine
Milkyway Intelligence | Author: Sharlix
Generates JSON, HTML, and TXT reports from scan results.
"""

import json
import os
import time
from datetime import datetime
from typing import List

from core.scanner import ScanResult


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>m7lfi Report – Milkyway Intelligence</title>
<style>
  :root {{
    --bg: #0a0a0f; --surface: #12121a; --border: #1e1e2e;
    --green: #00ff88; --red: #ff4444; --yellow: #ffcc00;
    --text: #e0e0e0; --muted: #666;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; padding: 2rem; }}
  h1 {{ color: var(--green); font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .subtitle {{ color: var(--muted); margin-bottom: 2rem; font-size: 0.85rem; }}
  .stats {{ display: flex; gap: 2rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); padding: 1rem 1.5rem; border-radius: 6px; }}
  .stat-val {{ font-size: 2rem; font-weight: bold; color: var(--green); }}
  .stat-lbl {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.2rem; }}
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }}
  .finding-header {{ padding: 1rem 1.5rem; display: flex; align-items: center; gap: 1rem; border-bottom: 1px solid var(--border); }}
  .badge-vuln {{ background: #ff4444; color: #fff; padding: 0.2rem 0.7rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
  .badge-clean {{ background: #333; color: #888; padding: 0.2rem 0.7rem; border-radius: 4px; font-size: 0.75rem; }}
  .finding-body {{ padding: 1.5rem; display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
  .field label {{ font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .field value {{ display: block; margin-top: 0.3rem; color: var(--text); word-break: break-all; }}
  .snippet {{ grid-column: 1/-1; background: #0d0d0d; border: 1px solid var(--border); border-radius: 4px; padding: 1rem; font-size: 0.8rem; color: var(--green); white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }}
  .curl-cmd {{ grid-column: 1/-1; background: #080808; border: 1px solid #1a3a1a; border-radius: 4px; padding: 0.8rem; font-size: 0.78rem; color: #4af; }}
  .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.75rem; text-align: center; }}
</style>
</head>
<body>
<h1>⚡ m7lfi – LFI Scan Report</h1>
<p class="subtitle">Milkyway Intelligence | Author: Sharlix | {timestamp}</p>

<div class="stats">
  <div class="stat"><div class="stat-val">{total}</div><div class="stat-lbl">URLs Scanned</div></div>
  <div class="stat"><div class="stat-val" style="color:var(--red)">{vulns}</div><div class="stat-lbl">Vulnerabilities</div></div>
  <div class="stat"><div class="stat-val">{duration}s</div><div class="stat-lbl">Duration</div></div>
</div>

{findings_html}

<div class="footer">m7lfi | For authorized security testing only | Milkyway Intelligence</div>
</body>
</html>
"""


class ReportEngine:
    """Generates reports in JSON, HTML, and TXT formats."""

    def __init__(self, output_dir: str = "output/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.start_time = time.time()

    def generate_all(self, results: List[ScanResult], scan_duration: float = 0) -> dict:
        """Generate all report formats. Returns dict of file paths."""
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        base     = os.path.join(self.output_dir, f"m7lfi_{ts}")
        duration = round(scan_duration or (time.time() - self.start_time), 1)

        paths = {
            "json": self._write_json(results, base + ".json"),
            "html": self._write_html(results, base + ".html", duration),
            "txt":  self._write_txt(results, base + ".txt"),
        }
        return paths

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _write_json(self, results: List[ScanResult], path: str) -> str:
        data = {
            "tool":      "m7lfi",
            "org":       "Milkyway Intelligence",
            "author":    "Sharlix",
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total":  len(results),
                "vulns":  sum(1 for r in results if r.vulnerable),
            },
            "findings": [self._result_to_dict(r) for r in results if r.vulnerable],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _write_html(self, results: List[ScanResult], path: str, duration: float) -> str:
        findings_html = ""
        for r in results:
            if not r.vulnerable:
                continue
            findings_html += f"""
<div class="finding">
  <div class="finding-header">
    <span class="badge-vuln">VULNERABLE</span>
    <span>{r.url}</span>
  </div>
  <div class="finding-body">
    <div class="field"><label>Parameter</label><value>{r.param}</value></div>
    <div class="field"><label>Status Code</label><value>{r.status_code}</value></div>
    <div class="field"><label>Payload</label><value>{r.payload}</value></div>
    <div class="field"><label>Bypass Used</label><value>{r.bypass_used or "None"}</value></div>
    <div class="snippet">{r.snippet[:800]}</div>
    <div class="curl-cmd">$ {r.curl_cmd}</div>
  </div>
</div>"""

        if not findings_html:
            findings_html = '<p style="color:var(--muted); margin: 2rem 0;">No vulnerabilities found.</p>'

        html = HTML_TEMPLATE.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total=len(results),
            vulns=sum(1 for r in results if r.vulnerable),
            duration=duration,
            findings_html=findings_html,
        )
        with open(path, "w") as f:
            f.write(html)
        return path

    # ── TXT ───────────────────────────────────────────────────────────────────

    def _write_txt(self, results: List[ScanResult], path: str) -> str:
        lines = [
            "=" * 70,
            "  m7lfi - LFI Scan Report | Milkyway Intelligence | Sharlix",
            "=" * 70,
            f"  Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Total URLs: {len(results)}",
            f"  Vulns     : {sum(1 for r in results if r.vulnerable)}",
            "=" * 70,
            "",
        ]
        for r in results:
            if not r.vulnerable:
                continue
            lines += [
                "[+] VULNERABILITY FOUND",
                f"    URL       : {r.url}",
                f"    Parameter : {r.param}",
                f"    Payload   : {r.payload}",
                f"    Bypass    : {r.bypass_used or 'None'}",
                f"    Status    : {r.status_code}",
                f"    Snippet   : {r.snippet[:300]}",
                f"    Reproduce : {r.curl_cmd}",
                "",
                "-" * 70,
                "",
            ]
        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _result_to_dict(self, r: ScanResult) -> dict:
        return {
            "url":           r.url,
            "parameter":     r.param,
            "payload":       r.payload,
            "bypass":        r.bypass_used,
            "status_code":   r.status_code,
            "snippet":       r.snippet[:500],
            "curl":          r.curl_cmd,
            "exploit_chains": r.exploit_chains,
        }
