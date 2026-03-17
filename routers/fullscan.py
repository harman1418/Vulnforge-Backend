from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from utils.database import scans_collection
import asyncio
import subprocess
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime
import requests as http_requests
from dotenv import load_dotenv
import uuid

load_dotenv()

router = APIRouter()

CF_ACCOUNT_ID = os.getenv("CF_ACCOUNT_ID")
CF_API_TOKEN = os.getenv("CF_API_TOKEN")


# ─── Tool Runners ─────────────────────────────────────────────────────────────

def run_portscan(target, scan_type="medium"):
    try:
        if scan_type == "light":
            cmd = ["nmap", "-T4", "-sV", "--top-ports", "1000", "--open", "-oX", "-", target]
            timeout = 300
        elif scan_type == "medium":
            cmd = ["nmap", "-T4", "-sV", "-sC", "-O", "--top-ports", "5000", "--open", "-oX", "-", target]
            timeout = 600
        else:
            cmd = ["nmap", "-T4", "-sV", "-sC", "-O", "-A", "-p-", "--open", "-oX", "-", target]
            timeout = 1800

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ports = []
        os_info = ""
        try:
            root = ET.fromstring(result.stdout)
            for host in root.findall('host'):
                os_match = host.find('./os/osmatch')
                if os_match is not None:
                    os_info = os_match.get('name', '')
                for port in host.findall('./ports/port'):
                    state = port.find('state')
                    service = port.find('service')
                    if state is not None and state.get('state') == 'open':
                        ports.append({
                            "port": port.get('portid'),
                            "protocol": port.get('protocol'),
                            "service": service.get('name') if service is not None else 'unknown',
                            "version": (service.get('product', '') + ' ' + service.get('version', '')).strip() if service is not None else '',
                            "extrainfo": service.get('extrainfo', '') if service is not None else '',
                        })
        except:
            pass
        return {"status": "success", "total": len(ports), "ports": ports, "os": os_info}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "total": 0, "ports": [], "os": ""}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_subdomain(target, scan_type="medium"):
    try:
        if scan_type == "light":
            cmd = ["subfinder", "-d", target, "-silent", "-timeout", "30"]
            timeout = 90
        elif scan_type == "medium":
            cmd = ["subfinder", "-d", target, "-silent", "-all", "-timeout", "60"]
            timeout = 180
        else:
            cmd = ["subfinder", "-d", target, "-silent", "-all", "-recursive", "-timeout", "120"]
            timeout = 360

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        subdomains = [l.strip() for l in result.stdout.splitlines() if l.strip()]

        if scan_type == "deep":
            try:
                dns_result = subprocess.run(
                    ["gobuster", "dns", "-d", target, "-w", "/usr/share/wordlists/dirb/common.txt", "-q", "--no-error"],
                    capture_output=True, text=True, timeout=300
                )
                for line in dns_result.stdout.splitlines():
                    if "Found:" in line:
                        sub = line.replace("Found:", "").strip()
                        if sub and sub not in subdomains:
                            subdomains.append(sub)
            except:
                pass

        return {"status": "success", "total": len(subdomains), "subdomains": list(set(subdomains))}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_whois(target):
    try:
        import whois
        w = whois.whois(target)
        return {
            "status": "success",
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": str(w.name_servers),
            "org": str(w.org),
            "country": str(w.country),
            "emails": str(w.emails),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_dns(target):
    try:
        import dns.resolver
        records = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            try:
                answers = dns.resolver.resolve(target, rtype)
                records[rtype] = [str(r) for r in answers]
            except:
                pass
        return {"status": "success", "records": records}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_headers(target, scan_type="medium"):
    try:
        import httpx
        import builtwith
        url = f"https://{target}" if not target.startswith("http") else target

        response = httpx.get(url, follow_redirects=True, timeout=30, verify=False)
        headers = dict(response.headers)

        try:
            technologies = builtwith.parse(url)
        except:
            technologies = {}

        security_headers = {
            "X-Frame-Options": headers.get("x-frame-options", "NOT SET"),
            "X-Content-Type-Options": headers.get("x-content-type-options", "NOT SET"),
            "Strict-Transport-Security": headers.get("strict-transport-security", "NOT SET"),
            "Content-Security-Policy": headers.get("content-security-policy", "NOT SET"),
            "X-XSS-Protection": headers.get("x-xss-protection", "NOT SET"),
            "Referrer-Policy": headers.get("referrer-policy", "NOT SET"),
            "Permissions-Policy": headers.get("permissions-policy", "NOT SET"),
        }

        result = {
            "status": "success",
            "server": headers.get("server", "Unknown"),
            "technologies": technologies,
            "security_headers": security_headers,
            "status_code": response.status_code,
            "headers": dict(list(headers.items())[:20]),
        }

        if scan_type in ["medium", "deep"]:
            try:
                options_resp = httpx.options(url, timeout=10, verify=False)
                result["allowed_methods"] = options_resp.headers.get("allow", "Unknown")
            except:
                pass

        return result
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_waf(target):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        result = subprocess.run(["wafw00f", url, "-a"], capture_output=True, text=True, timeout=60)
        output = result.stdout
        detected = "is behind" in output.lower()
        waf_name = "None detected"
        for line in output.splitlines():
            if "is behind" in line.lower():
                waf_name = line.strip()
        return {"status": "success", "detected": detected, "waf": waf_name}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_ssl(target, scan_type="medium"):
    try:
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        if scan_type == "light":
            cmd = ["sslyze", "--json_out=-", host]
        else:
            cmd = ["sslyze", "--json_out=-", "--regular", host]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        try:
            data = json.loads(result.stdout)
            scan = data["server_scan_results"][0]["scan_result"]
            return {
                "status": "success",
                "tls_1_0": scan.get("tls_1_0_cipher_suites", {}).get("status", ""),
                "tls_1_1": scan.get("tls_1_1_cipher_suites", {}).get("status", ""),
                "tls_1_2": scan.get("tls_1_2_cipher_suites", {}).get("status", ""),
                "tls_1_3": scan.get("tls_1_3_cipher_suites", {}).get("status", ""),
                "heartbleed": scan.get("heartbleed", {}).get("status", ""),
            }
        except:
            return {"status": "success", "raw": result.stdout[:300]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_nuclei(target, scan_type="medium"):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        if scan_type == "medium":
            cmd = ["nuclei", "-u", url, "-severity", "critical,high", "-json", "-silent", "-timeout", "10", "-rate-limit", "50"]
            timeout = 300
        else:
            cmd = ["nuclei", "-u", url, "-severity", "critical,high,medium", "-json", "-silent", "-timeout", "15", "-rate-limit", "100"]
            timeout = 600

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        findings = []
        for line in result.stdout.splitlines():
            try:
                f = json.loads(line)
                findings.append({
                    "template": f.get("template-id", ""),
                    "name": f.get("info", {}).get("name", ""),
                    "severity": f.get("info", {}).get("severity", ""),
                    "description": f.get("info", {}).get("description", "")[:200],
                    "matched_at": f.get("matched-at", ""),
                })
            except:
                pass
        return {"status": "success", "total": len(findings), "findings": findings}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_wpscan(target):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        result = subprocess.run(
            ["wpscan", "--url", url, "--format", "json", "--no-update", "--enumerate", "p,t,u"],
            capture_output=True, text=True, timeout=300
        )
        try:
            data = json.loads(result.stdout)
            return {
                "status": "success",
                "is_wordpress": True,
                "version": data.get("version", {}),
                "vulnerabilities": data.get("vulnerabilities", []),
                "plugins": list(data.get("plugins", {}).keys())[:10],
                "themes": list(data.get("themes", {}).keys())[:5],
                "users": list(data.get("users", {}).keys())[:10],
            }
        except:
            is_wp = "wordpress" in result.stdout.lower()
            return {"status": "success", "is_wordpress": is_wp}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_gobuster(target, scan_type="medium"):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        if scan_type == "medium":
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            timeout = 300
        else:
            wordlist = "/usr/share/wordlists/dirb/big.txt"
            timeout = 600

        result = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "50", "-q", "--no-progress", "-b", "404,403"],
            capture_output=True, text=True, timeout=timeout
        )
        findings = [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.startswith("Error")]
        return {"status": "success", "total": len(findings), "findings": findings[:50]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_nikto(target):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        result = subprocess.run(
            ["nikto", "-h", url, "-Format", "json", "-nointeractive", "-maxtime", "300"],
            capture_output=True, text=True, timeout=360
        )
        findings = []
        for line in result.stdout.splitlines():
            if "OSVDB" in line or "+ " in line:
                findings.append(line.strip())
        return {"status": "success", "total": len(findings), "findings": findings[:20]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_sqli(target):
    try:
        url = f"https://{target}" if not target.startswith("http") else target
        result = subprocess.run(
            ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=2",
             "--forms", "--crawl=3", "--random-agent", "-v", "0",
             "--output-dir=/tmp/sqlmap_deep"],
            capture_output=True, text=True, timeout=600
        )
        output = result.stdout
        vulnerable = "injectable" in output.lower() or "sqlmap identified" in output.lower()
        return {"status": "success", "vulnerable": vulnerable, "raw": output[:500]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── AI Analysis via Cloudflare ───────────────────────────────────────────────

def analyze_with_ai(target, scan_results, scan_type="medium"):
    try:
        limited_results = {
            "portscan": {
                "total": scan_results.get("portscan", {}).get("total", 0),
                "os": scan_results.get("portscan", {}).get("os", ""),
                "ports": scan_results.get("portscan", {}).get("ports", [])[:20],
            },
            "subdomain": {
                "total": scan_results.get("subdomain", {}).get("total", 0),
                "sample": scan_results.get("subdomain", {}).get("subdomains", [])[:10],
            },
            "whois": {
                "registrar": scan_results.get("whois", {}).get("registrar", ""),
                "org": scan_results.get("whois", {}).get("org", ""),
                "country": scan_results.get("whois", {}).get("country", ""),
            },
            "headers": {
                "server": scan_results.get("headers", {}).get("server", ""),
                "security_headers": scan_results.get("headers", {}).get("security_headers", {}),
                "technologies": scan_results.get("headers", {}).get("technologies", {}),
            },
            "waf": {
                "detected": scan_results.get("waf", {}).get("detected", False),
                "waf": scan_results.get("waf", {}).get("waf", ""),
            },
            "nuclei": {
                "total": scan_results.get("nuclei", {}).get("total", 0),
                "findings": scan_results.get("nuclei", {}).get("findings", [])[:5],
            },
        }

        prompt = f"""You are a senior penetration tester. Analyze this {scan_type} security scan of {target}.

Scan Data:
{json.dumps(limited_results, indent=2)}

Return ONLY this exact JSON with no markdown or explanation:
{{
  "risk_level": "CRITICAL or HIGH or MEDIUM or LOW",
  "executive_summary": "Professional 3-4 sentence summary of security posture and key risks found.",
  "critical_findings": [
    {{
      "title": "Finding title",
      "description": "Detailed explanation of the vulnerability and business impact",
      "severity": "CRITICAL or HIGH or MEDIUM or LOW",
      "evidence": "Specific data from scan proving this finding"
    }}
  ],
  "attack_recommendations": [
    {{
      "tool": "sqlmap or wpscan or nuclei or gobuster or hydra",
      "target": "exact url or ip to test",
      "reason": "why this attack vector exists based on scan data",
      "priority": "HIGH or MEDIUM or LOW"
    }}
  ],
  "remediation_steps": [
    {{
      "issue": "Specific security issue",
      "fix": "Detailed technical steps to fix this",
      "priority": "HIGH or MEDIUM or LOW"
    }}
  ],
  "security_score": 45
}}"""

        response = http_requests.post(
            f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/ai/run/@cf/meta/llama-3.1-8b-instruct",
            headers={
                "Authorization": f"Bearer {CF_API_TOKEN}",
                "Content-Type": "application/json"
            },
            json={"messages": [{"role": "user", "content": prompt}]},
            timeout=60
        )

        result = response.json()
        text = result.get("result", {}).get("response", "").strip()
        text = text.replace("```json", "").replace("```", "").strip()

        start = text.find('{')
        end = text.rfind('}') + 1
        if start >= 0 and end > start:
            text = text[start:end]

        # Fix common JSON issues
        import re
        text = re.sub(r',\s*}', '}', text)
        text = re.sub(r',\s*]', ']', text)

        try:
            return json.loads(text)
        except:
            # Try to extract partial JSON
            try:
                # Build minimal valid response from what we got
                return {
                    "risk_level": "MEDIUM",
                    "executive_summary": text[:300] if len(text) > 50 else "Analysis completed with partial results.",
                    "critical_findings": [],
                    "attack_recommendations": [],
                    "remediation_steps": [],
                    "security_score": 30
                }
            except:
                raise

    except Exception as e:
        return {
            "risk_level": "UNKNOWN",
            "executive_summary": f"AI analysis failed: {str(e)}",
            "critical_findings": [],
            "attack_recommendations": [],
            "remediation_steps": [],
            "security_score": 0
        }


def execute_ai_attacks(target, recommendations, scan_type="deep"):
    attack_results = []
    max_attacks = 2 if scan_type == "medium" else 4

    for rec in recommendations[:max_attacks]:
        tool = rec.get("tool", "")
        attack_target = rec.get("target", target)
        result = None

        if tool == "wpscan":
            result = run_wpscan(attack_target)
        elif tool == "nuclei":
            result = run_nuclei(attack_target, scan_type)
        elif tool == "gobuster":
            result = run_gobuster(attack_target, scan_type)
        elif tool == "sqlmap":
            result = run_sqli(attack_target)
        elif tool == "hydra":
            try:
                r = subprocess.run(
                    ["hydra", "-L", "/usr/share/wordlists/metasploit/common_passwords.txt",
                     "-P", "/usr/share/wordlists/metasploit/common_passwords.txt",
                     "-t", "4", "-f", attack_target, "ssh"],
                    capture_output=True, text=True, timeout=120
                )
                cracked = "login:" in r.stdout.lower()
                result = {"status": "success", "vulnerable": cracked}
            except Exception as e:
                result = {"status": "error", "message": str(e)}

        if result:
            attack_results.append({
                "tool": tool,
                "target": attack_target,
                "reason": rec.get("reason", ""),
                "priority": rec.get("priority", "MEDIUM"),
                "result": result
            })

    return attack_results


# ─── Professional PDF Report ──────────────────────────────────────────────────

def generate_report(target, scan_results, ai_analysis, attack_results, scan_type="medium"):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    DARK_BG  = colors.HexColor('#1f2937')
    GREEN    = colors.HexColor('#00c966')
    RED      = colors.HexColor('#ef4444')
    ORANGE   = colors.HexColor('#f97316')
    YELLOW   = colors.HexColor('#eab308')
    BLUE     = colors.HexColor('#3b82f6')
    GRAY     = colors.HexColor('#6b7280')
    LT_GRAY  = colors.HexColor('#f3f4f6')
    WHITE    = colors.white
    DARK     = colors.HexColor('#111827')
    BORDER   = colors.HexColor('#e5e7eb')

    risk = ai_analysis.get("risk_level", "UNKNOWN")
    scan_label = {"light": "LIGHT SCAN", "medium": "MEDIUM SCAN", "deep": "DEEP SCAN"}.get(scan_type, "SCAN")

    def rc(r):
        if r in ("CRITICAL",): return RED
        if r in ("HIGH",):     return ORANGE
        if r in ("MEDIUM",):   return YELLOW
        if r in ("LOW",):      return GREEN
        return GRAY

    pdf_path = f"/tmp/vulnforge_report_{target.replace('.', '_')}.pdf"
    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm)

    S = getSampleStyleSheet()

    def sty(name, **kw):
        return ParagraphStyle(name, parent=S['Normal'], **kw)

    sec  = sty('sec',  fontSize=13, fontName='Helvetica-Bold', textColor=DARK, leading=18, spaceBefore=14, spaceAfter=8)
    body = sty('body', fontSize=10, fontName='Helvetica', textColor=colors.HexColor('#374151'), leading=16, spaceAfter=6)
    mono = sty('mono', fontSize=9,  fontName='Courier',   textColor=colors.HexColor('#374151'), leading=14, spaceAfter=4)
    lbl  = sty('lbl',  fontSize=9,  fontName='Helvetica-Bold', textColor=GRAY, leading=13, spaceAfter=2)
    wht  = sty('wht',  fontSize=9,  fontName='Helvetica-Bold', textColor=WHITE)
    ctr  = sty('ctr',  fontSize=10, fontName='Helvetica', textColor=DARK, alignment=TA_CENTER, leading=16)

    story = []

    # ── Banner ───────────────────────────────────────────────────────────────
    banner = Table([["VULNFORGE"]], colWidths=[17*cm])
    banner.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), DARK_BG),
        ('TEXTCOLOR',     (0,0),(-1,-1), GREEN),
        ('FONTNAME',      (0,0),(-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0),(-1,-1), 20),
        ('ALIGN',         (0,0),(-1,-1), 'CENTER'),
        ('TOPPADDING',    (0,0),(-1,-1), 14),
        ('BOTTOMPADDING', (0,0),(-1,-1), 14),
    ]))
    story.append(banner)
    story.append(Spacer(1, 0.4*cm))

    # ── Cover ────────────────────────────────────────────────────────────────
    cover = Table([
        [Paragraph(f"PENETRATION TEST REPORT  |  {scan_label}", sty('ct', fontSize=9, fontName='Helvetica', textColor=GREEN)), ""],
        [Paragraph(target.upper(), sty('ch', fontSize=20, fontName='Helvetica-Bold', textColor=WHITE, leading=26)),
         Paragraph(f"Risk: {risk}", sty('cr', fontSize=14, fontName='Helvetica-Bold', textColor=rc(risk), alignment=TA_RIGHT))],
        [Paragraph(f"Date: {datetime.now().strftime('%B %d, %Y  %H:%M UTC')}", sty('cd', fontSize=9, fontName='Helvetica', textColor=colors.HexColor('#9ca3af'))),
         Paragraph(f"Score: {ai_analysis.get('security_score', 0)}/100", sty('cs', fontSize=14, fontName='Helvetica-Bold', textColor=rc(risk), alignment=TA_RIGHT))],
    ], colWidths=[12*cm, 5*cm])
    cover.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), DARK_BG),
        ('TOPPADDING',    (0,0),(-1,-1), 10),
        ('BOTTOMPADDING', (0,0),(-1,-1), 10),
        ('LEFTPADDING',   (0,0),(-1,-1), 16),
        ('RIGHTPADDING',  (0,0),(-1,-1), 16),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('LINEBELOW',     (0,1),(-1,1),  0.5, colors.HexColor('#374151')),
    ]))
    story.append(cover)
    story.append(Spacer(1, 0.4*cm))

    # ── Stats ────────────────────────────────────────────────────────────────
    ports      = scan_results.get("portscan",  {}).get("ports",      [])
    subdomains = scan_results.get("subdomain", {}).get("subdomains", [])
    findings_c = len(ai_analysis.get("critical_findings", []))
    nuclei_c   = scan_results.get("nuclei",   {}).get("total", 0)
    os_info    = scan_results.get("portscan",  {}).get("os",    "")

    stats = Table([[
        Paragraph(f"<b>{len(ports)}</b><br/>Open Ports",      ctr),
        Paragraph(f"<b>{len(subdomains)}</b><br/>Subdomains", ctr),
        Paragraph(f"<b>{findings_c}</b><br/>AI Findings",     ctr),
        Paragraph(f"<b>{nuclei_c}</b><br/>CVEs Found",        ctr),
        Paragraph(f"<b>{scan_label}</b><br/>Scan Type",       ctr),
    ]], colWidths=[3.4*cm]*5)
    stats.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), LT_GRAY),
        ('TOPPADDING',    (0,0),(-1,-1), 12),
        ('BOTTOMPADDING', (0,0),(-1,-1), 12),
        ('ALIGN',         (0,0),(-1,-1), 'CENTER'),
        ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ('LINEAFTER',     (0,0),(3,0),   0.5, BORDER),
        ('BOX',           (0,0),(-1,-1), 0.5, BORDER),
    ]))
    story.append(stats)
    story.append(Spacer(1, 0.8*cm))

    # ── 01 Executive Summary ─────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=2, color=GREEN, spaceAfter=8))
    story.append(Paragraph("01.  EXECUTIVE SUMMARY", sec))
    story.append(Paragraph(ai_analysis.get("executive_summary", "No summary available."), body))
    if os_info:
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(f"<b>Detected OS:</b>  {os_info}", body))
    story.append(Spacer(1, 0.4*cm))

    risk_tbl = Table([
        [Paragraph("RISK LEVEL", lbl),
         Paragraph("SECURITY SCORE", sty('l2', fontSize=9, fontName='Helvetica-Bold', textColor=GRAY, alignment=TA_CENTER)),
         Paragraph("SCAN TYPE", sty('l3', fontSize=9, fontName='Helvetica-Bold', textColor=GRAY, alignment=TA_RIGHT))],
        [Paragraph(risk, sty('rv', fontSize=20, fontName='Helvetica-Bold', textColor=rc(risk), leading=24)),
         Paragraph(f"{ai_analysis.get('security_score', 0)}/100", sty('sv', fontSize=20, fontName='Helvetica-Bold', textColor=DARK, leading=24, alignment=TA_CENTER)),
         Paragraph(scan_label, sty('st', fontSize=14, fontName='Helvetica-Bold', textColor=BLUE, leading=24, alignment=TA_RIGHT))],
    ], colWidths=[5.67*cm]*3)
    risk_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,-1), LT_GRAY),
        ('TOPPADDING',    (0,0),(-1,-1), 10),
        ('BOTTOMPADDING', (0,0),(-1,-1), 10),
        ('LEFTPADDING',   (0,0),(-1,-1), 14),
        ('RIGHTPADDING',  (0,0),(-1,-1), 14),
        ('BOX',           (0,0),(-1,-1), 0.5, BORDER),
        ('LINEAFTER',     (0,0),(1,-1),  0.5, BORDER),
        ('LINEBELOW',     (0,0),(-1,0),  0.5, BORDER),
    ]))
    story.append(risk_tbl)
    story.append(Spacer(1, 0.8*cm))

    # ── 02 Critical Findings ─────────────────────────────────────────────────
    crit = ai_analysis.get("critical_findings", [])
    if crit:
        story.append(HRFlowable(width="100%", thickness=2, color=RED, spaceAfter=8))
        story.append(Paragraph(f"02.  CRITICAL FINDINGS  ({len(crit)} identified)", sec))
        for i, f in enumerate(crit, 1):
            sev = f.get("severity", "MEDIUM")
            hdr = Table([[
                Paragraph(f"{i:02d}.  {f.get('title','')}", sty('ft', fontSize=11, fontName='Helvetica-Bold', textColor=DARK, leading=15)),
                Paragraph(sev, sty('fs', fontSize=9, fontName='Helvetica-Bold', textColor=rc(sev), alignment=TA_RIGHT))
            ]], colWidths=[13*cm, 4*cm])
            hdr.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,-1), LT_GRAY),
                ('TOPPADDING',    (0,0),(-1,-1), 8),
                ('BOTTOMPADDING', (0,0),(-1,-1), 8),
                ('LEFTPADDING',   (0,0),(-1,-1), 12),
                ('RIGHTPADDING',  (0,0),(-1,-1), 12),
                ('LINEBELOW',     (0,0),(-1,-1), 2, rc(sev)),
            ]))
            story.append(hdr)
            rows = [[Paragraph("Description", lbl), Paragraph(f.get("description",""), body)]]
            if f.get("evidence"):
                rows.append([Paragraph("Evidence", lbl), Paragraph(str(f["evidence"])[:300], mono)])
            det = Table(rows, colWidths=[3*cm, 14*cm])
            det.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,-1), WHITE),
                ('TOPPADDING',    (0,0),(-1,-1), 6),
                ('BOTTOMPADDING', (0,0),(-1,-1), 6),
                ('LEFTPADDING',   (0,0),(-1,-1), 12),
                ('RIGHTPADDING',  (0,0),(-1,-1), 12),
                ('VALIGN',        (0,0),(-1,-1), 'TOP'),
                ('BOX',           (0,0),(-1,-1), 0.5, BORDER),
                ('LINEAFTER',     (0,0),(0,-1),  0.5, BORDER),
            ]))
            story.append(det)
            story.append(Spacer(1, 0.3*cm))
        story.append(Spacer(1, 0.5*cm))

    # ── 03 Port Scan ─────────────────────────────────────────────────────────
    if ports:
        story.append(HRFlowable(width="100%", thickness=2, color=BLUE, spaceAfter=8))
        story.append(Paragraph(f"03.  OPEN PORTS & SERVICES  ({len(ports)} found)", sec))
        rows = [[Paragraph(h, wht) for h in ["PORT","PROTO","SERVICE","VERSION / BANNER"]]]
        for p in ports:
            ver = p.get("version","") or p.get("extrainfo","")
            rows.append([
                Paragraph(str(p.get("port","")), mono),
                Paragraph(str(p.get("protocol","")), body),
                Paragraph(str(p.get("service","")), body),
                Paragraph(str(ver)[:60], body),
            ])
        pt = Table(rows, colWidths=[2*cm, 2.5*cm, 4*cm, 8.5*cm])
        pt.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,0),  DARK_BG),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LT_GRAY]),
            ('TOPPADDING',    (0,0),(-1,-1),  7),
            ('BOTTOMPADDING', (0,0),(-1,-1),  7),
            ('LEFTPADDING',   (0,0),(-1,-1),  10),
            ('RIGHTPADDING',  (0,0),(-1,-1),  10),
            ('VALIGN',        (0,0),(-1,-1),  'MIDDLE'),
            ('BOX',           (0,0),(-1,-1),  0.5, BORDER),
            ('INNERGRID',     (0,0),(-1,-1),  0.3, BORDER),
        ]))
        story.append(pt)
        story.append(Spacer(1, 0.8*cm))

    # ── 04 Subdomains ────────────────────────────────────────────────────────
    if subdomains:
        story.append(HRFlowable(width="100%", thickness=2, color=BLUE, spaceAfter=8))
        story.append(Paragraph(f"04.  SUBDOMAINS DISCOVERED  ({len(subdomains)} found)", sec))
        display = subdomains[:60]
        rows = []
        for i in range(0, len(display), 2):
            rows.append([
                Paragraph(display[i], mono),
                Paragraph(display[i+1] if i+1 < len(display) else "", mono)
            ])
        st = Table(rows, colWidths=[8.5*cm, 8.5*cm])
        st.setStyle(TableStyle([
            ('ROWBACKGROUNDS',(0,0),(-1,-1),[WHITE, LT_GRAY]),
            ('TOPPADDING',    (0,0),(-1,-1), 5),
            ('BOTTOMPADDING', (0,0),(-1,-1), 5),
            ('LEFTPADDING',   (0,0),(-1,-1), 10),
            ('RIGHTPADDING',  (0,0),(-1,-1), 10),
            ('BOX',           (0,0),(-1,-1), 0.5, BORDER),
            ('INNERGRID',     (0,0),(-1,-1), 0.3, BORDER),
        ]))
        story.append(st)
        if len(subdomains) > 60:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(f"... and {len(subdomains)-60} more subdomains discovered.", body))
        story.append(Spacer(1, 0.8*cm))

    # ── 05 Tech & Headers ────────────────────────────────────────────────────
    techs    = scan_results.get("headers",{}).get("technologies",{})
    sec_hdrs = scan_results.get("headers",{}).get("security_headers",{})
    dns_info = scan_results.get("dns",{}).get("records",{})

    if techs or sec_hdrs or dns_info:
        story.append(HRFlowable(width="100%", thickness=2, color=BLUE, spaceAfter=8))
        story.append(Paragraph("05.  TECHNOLOGY & HEADER ANALYSIS", sec))

        if techs:
            story.append(Paragraph("Technologies Detected", sty('sub', fontSize=11, fontName='Helvetica-Bold', textColor=DARK, spaceAfter=6, spaceBefore=4)))
            items = [item for vals in techs.values() for item in vals]
            if items:
                rows = []
                for i in range(0, len(items), 3):
                    rows.append([Paragraph(items[j] if j < len(items) else "", mono) for j in range(i, i+3)])
                tt = Table(rows, colWidths=[5.67*cm]*3)
                tt.setStyle(TableStyle([
                    ('ROWBACKGROUNDS',(0,0),(-1,-1),[WHITE, LT_GRAY]),
                    ('TOPPADDING',    (0,0),(-1,-1), 5),
                    ('BOTTOMPADDING', (0,0),(-1,-1), 5),
                    ('LEFTPADDING',   (0,0),(-1,-1), 10),
                    ('RIGHTPADDING',  (0,0),(-1,-1), 10),
                    ('BOX',           (0,0),(-1,-1), 0.5, BORDER),
                    ('INNERGRID',     (0,0),(-1,-1), 0.3, BORDER),
                ]))
                story.append(tt)
                story.append(Spacer(1, 0.4*cm))

        if sec_hdrs:
            story.append(Paragraph("Security Headers", sty('sub2', fontSize=11, fontName='Helvetica-Bold', textColor=DARK, spaceAfter=6, spaceBefore=4)))
            hrows = [[Paragraph("HEADER", wht), Paragraph("VALUE / STATUS", wht)]]
            for h, v in sec_hdrs.items():
                not_set = "NOT SET" in str(v) or "Missing" in str(v)
                hrows.append([
                    Paragraph(h, body),
                    Paragraph("NOT SET - MISSING", sty('hv', fontSize=9, fontName='Helvetica-Bold', textColor=RED, leading=14))
                    if not_set else
                    Paragraph(str(v)[:80], sty('hv2', fontSize=9, fontName='Helvetica', textColor=GREEN, leading=14))
                ])
            ht = Table(hrows, colWidths=[7*cm, 10*cm])
            ht.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,0),  DARK_BG),
                ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LT_GRAY]),
                ('TOPPADDING',    (0,0),(-1,-1),  6),
                ('BOTTOMPADDING', (0,0),(-1,-1),  6),
                ('LEFTPADDING',   (0,0),(-1,-1),  10),
                ('RIGHTPADDING',  (0,0),(-1,-1),  10),
                ('BOX',           (0,0),(-1,-1),  0.5, BORDER),
                ('INNERGRID',     (0,0),(-1,-1),  0.3, BORDER),
            ]))
            story.append(ht)
            story.append(Spacer(1, 0.5*cm))

        if dns_info:
            story.append(Paragraph("DNS Records", sty('sub3', fontSize=11, fontName='Helvetica-Bold', textColor=DARK, spaceAfter=6, spaceBefore=4)))
            drows = [[Paragraph("TYPE", wht), Paragraph("RECORDS", wht)]]
            for rtype, vals in dns_info.items():
                drows.append([
                    Paragraph(rtype, sty('dt', fontSize=10, fontName='Helvetica-Bold', textColor=BLUE)),
                    Paragraph(", ".join(str(v) for v in vals[:5]), mono)
                ])
            dt = Table(drows, colWidths=[3*cm, 14*cm])
            dt.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,0),  DARK_BG),
                ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LT_GRAY]),
                ('TOPPADDING',    (0,0),(-1,-1),  6),
                ('BOTTOMPADDING', (0,0),(-1,-1),  6),
                ('LEFTPADDING',   (0,0),(-1,-1),  10),
                ('RIGHTPADDING',  (0,0),(-1,-1),  10),
                ('BOX',           (0,0),(-1,-1),  0.5, BORDER),
                ('INNERGRID',     (0,0),(-1,-1),  0.3, BORDER),
            ]))
            story.append(dt)
            story.append(Spacer(1, 0.8*cm))

    # ── 06 Nuclei CVE Findings ───────────────────────────────────────────────
    nuclei_findings = scan_results.get("nuclei", {}).get("findings", [])
    if nuclei_findings:
        story.append(HRFlowable(width="100%", thickness=2, color=RED, spaceAfter=8))
        story.append(Paragraph(f"06.  CVE / NUCLEI FINDINGS  ({len(nuclei_findings)} found)", sec))
        nrows = [[Paragraph(h, wht) for h in ["SEVERITY","TEMPLATE","NAME","MATCHED AT"]]]
        for nf in nuclei_findings[:30]:
            sev = nf.get("severity","").upper()
            nrows.append([
                Paragraph(sev, sty('ns', fontSize=9, fontName='Helvetica-Bold', textColor=rc(sev))),
                Paragraph(str(nf.get("template",""))[:25], mono),
                Paragraph(str(nf.get("name",""))[:40], body),
                Paragraph(str(nf.get("matched_at",""))[:40], mono),
            ])
        nt = Table(nrows, colWidths=[2.5*cm, 4*cm, 6*cm, 4.5*cm])
        nt.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,0),  DARK_BG),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [WHITE, LT_GRAY]),
            ('TOPPADDING',    (0,0),(-1,-1),  6),
            ('BOTTOMPADDING', (0,0),(-1,-1),  6),
            ('LEFTPADDING',   (0,0),(-1,-1),  8),
            ('RIGHTPADDING',  (0,0),(-1,-1),  8),
            ('BOX',           (0,0),(-1,-1),  0.5, BORDER),
            ('INNERGRID',     (0,0),(-1,-1),  0.3, BORDER),
        ]))
        story.append(nt)
        story.append(Spacer(1, 0.8*cm))

    # ── 07 AI Attack Results ─────────────────────────────────────────────────
    if attack_results:
        story.append(PageBreak())
        story.append(HRFlowable(width="100%", thickness=2, color=ORANGE, spaceAfter=8))
        story.append(Paragraph(f"07.  AI-DIRECTED ATTACK RESULTS  ({len(attack_results)} executed)", sec))
        for a in attack_results:
            vuln = a.get("result",{}).get("vulnerable")
            at = Table([[
                Paragraph(f"Tool: {a.get('tool','').upper()}", sty('atl', fontSize=11, fontName='Helvetica-Bold', textColor=ORANGE, leading=15)),
                Paragraph("VULNERABLE" if vuln else "Not Vulnerable",
                    sty('av', fontSize=10, fontName='Helvetica-Bold',
                        textColor=RED if vuln else GREEN, alignment=TA_RIGHT))
            ],[
                Paragraph(f"Reason: {a.get('reason','')}", sty('ar', fontSize=9, fontName='Helvetica', textColor=GRAY, leading=13)),
                Paragraph(f"Target: {a.get('target','')}", sty('atg', fontSize=9, fontName='Helvetica', textColor=GRAY, alignment=TA_RIGHT))
            ]], colWidths=[10*cm, 7*cm])
            at.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,-1), LT_GRAY),
                ('TOPPADDING',    (0,0),(-1,-1), 8),
                ('BOTTOMPADDING', (0,0),(-1,-1), 8),
                ('LEFTPADDING',   (0,0),(-1,-1), 12),
                ('RIGHTPADDING',  (0,0),(-1,-1), 12),
                ('BOX',           (0,0),(-1,-1), 0.5, BORDER),
                ('LINEBELOW',     (0,0),(-1,0),  0.5, BORDER),
            ]))
            story.append(at)
            story.append(Spacer(1, 0.3*cm))
        story.append(Spacer(1, 0.5*cm))

    # ── 08 Remediation ───────────────────────────────────────────────────────
    rems = ai_analysis.get("remediation_steps", [])
    if rems:
        story.append(HRFlowable(width="100%", thickness=2, color=GREEN, spaceAfter=8))
        story.append(Paragraph(f"08.  REMEDIATION RECOMMENDATIONS  ({len(rems)} steps)", sec))
        for i, s in enumerate(rems, 1):
            pri = s.get("priority","MEDIUM")
            rt = Table([[
                Paragraph(f"{i:02d}.  {s.get('issue','')}", sty('ri', fontSize=11, fontName='Helvetica-Bold', textColor=DARK, leading=15)),
                Paragraph(f"Priority: {pri}", sty('rp', fontSize=9, fontName='Helvetica-Bold', textColor=rc(pri), alignment=TA_RIGHT))
            ],[
                Paragraph(s.get("fix",""), body), ""
            ]], colWidths=[13*cm, 4*cm])
            rt.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,0),  LT_GRAY),
                ('BACKGROUND',    (0,1),(-1,1),  WHITE),
                ('TOPPADDING',    (0,0),(-1,-1),  8),
                ('BOTTOMPADDING', (0,0),(-1,-1),  8),
                ('LEFTPADDING',   (0,0),(-1,-1),  12),
                ('RIGHTPADDING',  (0,0),(-1,-1),  12),
                ('VALIGN',        (0,0),(-1,-1),  'TOP'),
                ('BOX',           (0,0),(-1,-1),  0.5, BORDER),
                ('LINEBELOW',     (0,0),(-1,0),   0.5, BORDER),
                ('SPAN',          (0,1),(1,1)),
            ]))
            story.append(rt)
            story.append(Spacer(1, 0.25*cm))
        story.append(Spacer(1, 0.5*cm))

    # ── Footer ───────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=6))
    ft = Table([[
        Paragraph("Generated by VulnForge — Autonomous Penetration Testing Platform",
            sty('f1', fontSize=8, fontName='Helvetica', textColor=GRAY)),
        Paragraph(f"Report: {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC  |  Scan: {scan_label}",
            sty('f2', fontSize=8, fontName='Helvetica', textColor=GRAY, alignment=TA_RIGHT))
    ]], colWidths=[10*cm, 7*cm])
    ft.setStyle(TableStyle([
        ('TOPPADDING',    (0,0),(-1,-1), 4),
        ('BOTTOMPADDING', (0,0),(-1,-1), 4),
        ('LEFTPADDING',   (0,0),(-1,-1), 0),
        ('RIGHTPADDING',  (0,0),(-1,-1), 0),
    ]))
    story.append(ft)
    doc.build(story)
    return pdf_path


# ─── WebSocket Full Scan ──────────────────────────────────────────────────────

@router.websocket("/ws/{scan_type}/{target:path}")
async def full_scan_ws(websocket: WebSocket, target: str, scan_type: str = "medium"):
    await websocket.accept()

    if scan_type not in ["light", "medium", "deep"]:
        scan_type = "medium"

    async def send(phase, tool, status, data=None):
        await websocket.send_json({
            "phase": phase,
            "tool": tool,
            "status": status,
            "data": data,
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat()
        })

    scan_results = {}

    try:
        await send(1, "Port Scanner", "running")
        scan_results["portscan"] = await asyncio.get_event_loop().run_in_executor(None, run_portscan, target, scan_type)
        await send(1, "Port Scanner", "done", scan_results["portscan"])

        await send(1, "Subdomain Finder", "running")
        scan_results["subdomain"] = await asyncio.get_event_loop().run_in_executor(None, run_subdomain, target, scan_type)
        await send(1, "Subdomain Finder", "done", scan_results["subdomain"])

        await send(1, "Whois Lookup", "running")
        scan_results["whois"] = await asyncio.get_event_loop().run_in_executor(None, run_whois, target)
        await send(1, "Whois Lookup", "done", scan_results["whois"])

        await send(1, "DNS Lookup", "running")
        scan_results["dns"] = await asyncio.get_event_loop().run_in_executor(None, run_dns, target)
        await send(1, "DNS Lookup", "done", scan_results["dns"])

        await send(1, "Header Scanner", "running")
        scan_results["headers"] = await asyncio.get_event_loop().run_in_executor(None, run_headers, target, scan_type)
        await send(1, "Header Scanner", "done", scan_results["headers"])

        await send(1, "WAF Detector", "running")
        scan_results["waf"] = await asyncio.get_event_loop().run_in_executor(None, run_waf, target)
        await send(1, "WAF Detector", "done", scan_results["waf"])

        await send(1, "SSL Scanner", "running")
        scan_results["ssl"] = await asyncio.get_event_loop().run_in_executor(None, run_ssl, target, scan_type)
        await send(1, "SSL Scanner", "done", scan_results["ssl"])

        if scan_type in ["medium", "deep"]:
            await send(1, "CVE Scanner", "running")
            scan_results["nuclei"] = await asyncio.get_event_loop().run_in_executor(None, run_nuclei, target, scan_type)
            await send(1, "CVE Scanner", "done", scan_results["nuclei"])

            await send(1, "URL Fuzzer", "running")
            scan_results["gobuster"] = await asyncio.get_event_loop().run_in_executor(None, run_gobuster, target, scan_type)
            await send(1, "URL Fuzzer", "done", scan_results["gobuster"])

        if scan_type == "deep":
            await send(1, "Nikto Scanner", "running")
            scan_results["nikto"] = await asyncio.get_event_loop().run_in_executor(None, run_nikto, target)
            await send(1, "Nikto Scanner", "done", scan_results["nikto"])

            await send(1, "WordPress Scanner", "running")
            scan_results["wpscan"] = await asyncio.get_event_loop().run_in_executor(None, run_wpscan, target)
            await send(1, "WordPress Scanner", "done", scan_results["wpscan"])

        await send(2, "Cloudflare AI", "running")
        ai_analysis = await asyncio.get_event_loop().run_in_executor(None, analyze_with_ai, target, scan_results, scan_type)
        await send(2, "Cloudflare AI", "done", ai_analysis)

        attack_results = []
        if scan_type in ["medium", "deep"]:
            await send(3, "AI Attack Engine", "running")
            attack_results = await asyncio.get_event_loop().run_in_executor(
                None, execute_ai_attacks, target, ai_analysis.get("attack_recommendations", []), scan_type)
            await send(3, "AI Attack Engine", "done", {"attacks": attack_results})
        else:
            await send(3, "AI Attack Engine", "skipped", {"message": "Not included in light scan"})

        await send(4, "Report Generator", "running")
        report_path = await asyncio.get_event_loop().run_in_executor(
            None, generate_report, target, scan_results, ai_analysis, attack_results, scan_type)

        scan_id = str(uuid.uuid4())
        await scans_collection.insert_one({
            "_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "scan_results": scan_results,
            "ai_analysis": ai_analysis,
            "attack_results": attack_results,
            "report_path": report_path,
            "created_at": datetime.now().isoformat(),
            "risk_level": ai_analysis.get("risk_level", "UNKNOWN"),
            "security_score": ai_analysis.get("security_score", 0),
        })

        await send(4, "Report Generator", "done", {
            "report_path": report_path,
            "scan_id": scan_id,
            "download_url": f"/api/fullscan/download/{target.replace('.', '_')}"
        })

        await send(4, "VulnForge", "complete", {
            "scan_results": scan_results,
            "ai_analysis": ai_analysis,
            "attack_results": attack_results,
            "scan_id": scan_id,
            "scan_type": scan_type,
            "download_url": f"/api/fullscan/download/{target.replace('.', '_')}"
        })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await send(0, "VulnForge", "error", {"message": str(e)})


@router.get("/download/{filename}")
def download_report(filename: str):
    path = f"/tmp/vulnforge_report_{filename}.pdf"
    if os.path.exists(path):
        return FileResponse(path, filename=f"vulnforge_report_{filename}.pdf", media_type="application/pdf")
    return {"status": "error", "message": "Report not found"}
