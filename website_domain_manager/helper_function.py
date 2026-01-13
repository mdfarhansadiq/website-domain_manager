import json
import ast
import dns.resolver
import re
import socket
import ssl
import datetime
import requests
import whois


# Regular expression to validate domain names
DOMAIN_REGEX = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")



def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.fullmatch(domain))

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
        }
    except Exception:
        return {}


def get_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {"ip_address": ip}
    except Exception:
        return {}


def get_server_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json").json()
        return {
            "country": response.get("country"),
            "region": response.get("region"),
        }
    except Exception:
        print("Error fetching server location")
        return {}


def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        return {
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "valid_from": cert.get("notBefore"),
            "valid_to": cert.get("notAfter"),
        }
    except Exception:
        return {}


def get_http_status(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return {"status_code": response.status_code, "available": True}
    except requests.RequestException:
        return {"status_code": None, "available": False}


def get_dns_records(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 4

    records = {}

    for t in ["A", "CNAME", "TXT"]:
        try:
            records[t] = [r.to_text() for r in resolver.resolve(domain, t)]
        except Exception:
            records[t] = []

    return records


def is_ip_address(value):
    try:
        socket.inet_aton(value)
        return True
    except socket.error:
        return False


def json_safe(data):
    if isinstance(data, dict):
        return {k: json_safe(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [json_safe(item) for item in data]
    elif isinstance(data, (datetime.date, datetime.datetime)):
        return data.isoformat()  # Converts to "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SS"
    return data