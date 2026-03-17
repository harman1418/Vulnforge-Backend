from fastapi import APIRouter
import whois

router = APIRouter()

@router.get("/")
def whois_lookup(target: str):
    try:
        w = whois.whois(target)

        return {
            "target": target,
            "status": "success",
            "data": {
                "domain_name": str(w.domain_name),
                "registrar": str(w.registrar),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": str(w.name_servers),
                "status": str(w.status),
                "emails": str(w.emails),
                "org": str(w.org),
                "country": str(w.country),
            }
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}
