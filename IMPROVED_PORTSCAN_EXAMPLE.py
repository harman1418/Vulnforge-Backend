"""
UPDATED PORTSCAN ROUTER WITH SECURITY IMPROVEMENTS
Example of improved error handling, input validation, and logging
"""
from fastapi import APIRouter, Depends, HTTPException
from utils.security import sanitize_target, escape_subprocess_arg
from utils.logger import log_info, log_error, log_security_event
from routers.auth import get_current_user
import subprocess
import xml.etree.ElementTree as ET

router = APIRouter()

def escape_subprocess_arg(arg: str) -> str:
    """Escape arguments for subprocess to prevent injection"""
    # Allow only safe characters
    import re
    if not re.match(r'^[a-zA-Z0-9._\-/:]*$', arg):
        raise ValueError(f"Invalid characters in argument: {arg}")
    return arg


def parse_nmap_xml(xml_output):
    """Parse nmap XML output safely"""
    try:
        root = ET.fromstring(xml_output)
        ports = []
        for host in root.findall("host"):
            for port in host.findall("ports/port"):
                port_id = port.get("portid", "")
                protocol = port.get("protocol", "tcp")
                state = port.find("state").get("state", "unknown") if port.find("state") is not None else "unknown"
                service_elem = port.find("service")
                service = service_elem.get("name", "") if service_elem is not None else ""
                
                ports.append({
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service
                })
        return ports
    except ET.ParseError as e:
        log_error("Failed to parse nmap XML", error=e)
        return []


@router.get("/")
async def port_scan(
    target: str,
    scan_type: str = "basic",
    current_user: str = Depends(get_current_user)
):
    """
    Port scan with nmap
    
    Args:
        target: Domain or IP to scan
        scan_type: basic, full, service, or udp
        current_user: Authenticated user email
    
    Returns:
        Scan results with open ports
    """
    try:
        # ─── Input Validation ───────────────────────────────────────────
        try:
            target = sanitize_target(target)
        except ValueError as e:
            log_security_event("INVALID_TARGET", user=current_user, details=str(e))
            raise HTTPException(status_code=400, detail=f"Invalid target: {e}")
        
        # Validate scan type
        if scan_type not in ["basic", "full", "service", "udp"]:
            raise HTTPException(status_code=400, detail="Invalid scan_type")
        
        log_info(f"Starting port scan: {scan_type}", user=current_user, target=target)
        
        # ─── Build Command ──────────────────────────────────────────────
        try:
            clean_target = escape_subprocess_arg(target.replace("https://", "").replace("http://", "").split("/")[0])
        except ValueError as e:
            log_security_event("SUBPROCESS_INJECTION_ATTEMPT", user=current_user, target=target)
            raise HTTPException(status_code=400, detail="Invalid target format")
        
        if scan_type == "basic":
            cmd = ["nmap", "-T4", "-F", "--open", "-oX", "-", clean_target]
        elif scan_type == "full":
            cmd = ["nmap", "-T4", "-p-", "--open", "-oX", "-", clean_target]
        elif scan_type == "service":
            cmd = ["nmap", "-T4", "-sV", "-sC", "--open", "-oX", "-", clean_target]
        elif scan_type == "udp":
            cmd = ["sudo", "nmap", "-sU", "-T4", "--open", "-oX", "-", clean_target]
        
        # ─── Execute Scan ───────────────────────────────────────────────
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False
            )
        except subprocess.TimeoutExpired:
            log_error("Port scan timeout", user=current_user, target=target)
            raise HTTPException(status_code=408, detail="Scan timed out")
        except Exception as e:
            log_error("Port scan execution error", error=e, user=current_user, target=target)
            raise HTTPException(status_code=500, detail="Scan execution failed")
        
        # ─── Parse Results ──────────────────────────────────────────────
        ports = parse_nmap_xml(result.stdout)
        
        log_info(
            f"Port scan completed: {len(ports)} ports found",
            user=current_user,
            target=target,
            scan_type=scan_type,
            ports_found=len(ports)
        )
        
        return {
            "target": target,
            "scan_type": scan_type,
            "status": "success",
            "total_open_ports": len(ports),
            "ports": ports
        }
    
    except HTTPException:
        raise
    except Exception as e:
        log_error("Unexpected error in port scan", error=e, user=current_user)
        raise HTTPException(status_code=500, detail="Port scan failed")
