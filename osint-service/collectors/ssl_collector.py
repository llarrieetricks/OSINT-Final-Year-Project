
import socket
import ssl
from datetime import datetime, timezone


SSL_TIMEOUT = 8


def get_ssl_data(hostname):
    if not hostname or not isinstance(hostname, str):
        raise ValueError("A valid hostname is required.")

    hostname = hostname.strip().lower().rstrip(".")

    if not hostname:
        raise ValueError("A valid hostname is required.")

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, 443),
            timeout=SSL_TIMEOUT
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=hostname
            ) as secure_connection:

                certificate = secure_connection.getpeercert()

                subject = dict(
                    (key, value)
                    for item in certificate.get("subject", [])
                    for key, value in item
                )

                issuer = dict(
                    (key, value)
                    for item in certificate.get("issuer", [])
                    for key, value in item
                )

                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")

                expiration_date = (
                    datetime.strptime(
                        not_after,
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    if not_after else None
                )

                now = datetime.now(timezone.utc)

                return {
                    "hostname": hostname,
                    "subject": subject,
                    "issuer": issuer,
                    "subjectAlternativeNames": [
                        value
                        for name_type, value
                        in certificate.get("subjectAltName", [])
                        if name_type == "DNS"
                    ],
                    "serialNumber": certificate.get("serialNumber"),
                    "version": certificate.get("version"),
                    "notBefore": not_before,
                    "notAfter": not_after,
                    "expired": (
                        expiration_date < now
                        if expiration_date else None
                    ),
                    "daysUntilExpiry": (
                        (expiration_date - now).days
                        if expiration_date else None
                    ),
                    "collectedAt": now.isoformat(),
                    "valid": True,
                    "error": None
                }

    except ssl.SSLCertVerificationError as error:
        return {
            "hostname": hostname,
            "valid": False,
            "error": f"Certificate verification failed: {error}"
        }

    except (socket.timeout, TimeoutError):
        return {
            "hostname": hostname,
            "valid": False,
            "error": "SSL connection timed out."
        }

    except Exception as error:
        return {
            "hostname": hostname,
            "valid": False,
            "error": str(error)
        }




