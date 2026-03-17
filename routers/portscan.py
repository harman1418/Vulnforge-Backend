from fastapi import APIRouter
import subprocess
import xml.etree.ElementTree as ET

router = APIRouter()

def parse_nmap_xml(xml_output):
    ports = []
    try:
        root = ET.fromstring(xml_output)
        for host in root.findall('host'):
            for port in host.findall('./ports/port'):
                state = port.find('state')
                service = port.find('service')
                if state is not None and state.get('state') == 'open':
                    ports.append({
                        "port": port.get('portid'),
                        "protocol": port.get('protocol'),
                        "state": state.get('state'),
                        "service": service.get('name') if service is not None else 'unknown',
                        "version": service.get('product', '') + ' ' + service.get('version', '') if service is not None else ''
                    })
    except Exception as e:
        pass
    return ports

@router.get("/")
def port_scan(target: str, scan_type: str = "basic"):
    try:
        if scan_type == "basic":
            cmd = ["nmap", "-T4", "-F", "--open", "-oX", "-", target]
        elif scan_type == "full":
            cmd = ["nmap", "-T4", "-p-", "--open", "-oX", "-", target]
        elif scan_type == "service":
            cmd = ["nmap", "-T4", "-sV", "-sC", "--open", "-oX", "-", target]
        elif scan_type == "udp":
            cmd = ["sudo", "nmap", "-sU", "-T4", "--open", "-oX", "-", target]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        ports = parse_nmap_xml(result.stdout)

        return {
            "target": target,
            "scan_type": scan_type,
            "status": "success",
            "total_open_ports": len(ports),
            "ports": ports
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
