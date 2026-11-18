
import whois
from datetime import datetime, date


def serialize_date(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, list):
        return [serialize_date(item) for item in value]

    return value


def get_whois_data(domain):
    if not domain or not isinstance(domain, str):
        raise ValueError("A valid domain is required.")

    domain = domain.strip().lower()

    try:
        result = whois.whois(domain)

        return {
            "domain": domain,
            "registrar": result.get("registrar"),
            "creationDate": serialize_date(result.get("creation_date")),
            "expirationDate": serialize_date(result.get("expiration_date")),
            "updatedDate": serialize_date(result.get("updated_date")),
            "nameServers": result.get("name_servers") or [],
            "status": result.get("status") or [],
            "emails": result.get("emails") or [],
            "country": result.get("country"),
            "organization": result.get("org"),
            "collectedAt": datetime.utcnow().isoformat()
        }

    except Exception as error:
        return {
            "domain": domain,
            "error": str(error),
            "registrar": None,
            "creationDate": None,
            "expirationDate": None,
            "updatedDate": None,
            "nameServers": [],
            "status": [],
            "emails": [],
            "country": None,
            "organization": None
        }
