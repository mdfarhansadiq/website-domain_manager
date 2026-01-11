import ast
import json
from django.shortcuts import (
    render,
    HttpResponseRedirect,
    HttpResponse,
    redirect,
    get_object_or_404,
)
from django.db.models import Q
import dns.resolver
import re
import socket
import ssl
import datetime
import requests
import whois
from .models import WebsiteDomainInfo

# Regular expression to validate domain names
DOMAIN_REGEX = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")


# Create your views here.
def index(request):
    domains = WebsiteDomainInfo.objects.all()
    return render(request, "index.html", {"domains": domains})


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


def fetch_info(request):
    domain_info = None
    error = None
    success = None
    domain = None

    if request.method == "POST":
        input_value = request.POST.get("domain_name", "").strip().lower()

        # 2️⃣ Check if domain already exists (single query)
        if is_ip_address(input_value):
            existing = WebsiteDomainInfo.objects.filter(
                ip_info__ip_address=input_value
            ).first()
        else:
            existing = WebsiteDomainInfo.objects.filter(domain_name=input_value).first()
            domain = input_value
        if existing:
            print("FOUND IN DB:", existing)
            print(type(existing.server_location))
            success = "Domain information retrieved from database."
            return render(
                request,
                "website_domain_info_details.html",
                {"domain_info": existing, "error": None, "success": success},
            )

        try:
            # 1️⃣ Validate input
            if not is_valid_domain(input_value) and not is_ip_address(input_value):
                error = "Invalid domain name or IP address."
                domains = WebsiteDomainInfo.objects.all()
                unique_countries = set()

                for d in WebsiteDomainInfo.objects.all():
                    if d.server_location:
                        try:
                            location = ast.literal_eval(d.server_location)
                            unique_countries.add(
                                location.get("country")
                                if location.get("country") != "None"
                                else "Unknown"
                            )
                        except Exception:
                            pass
                countries = list(unique_countries)

                print("ERROR:", error)
                return render(
                    request,
                    "index.html",
                    {
                        "domain_info": None,
                        "error": error,
                        "domains": domains,
                        "countries": countries,
                    },
                )

            # 3️⃣ Fetch all information concurrently
            # If it's an IP, we can't get WHOIS or DNS directly from it
            if is_ip_address(input_value):
                domain = input_value  # Treat IP as the domain for fetching
                try:
                    hostname, _, _ = socket.gethostbyaddr(input_value)
                    domain = hostname.rstrip(".")
                except Exception:
                    domain = input_value
                ip_info = {"ip_address": input_value}
                whois_info = {}
                dns_info = {}
                ssl_info = {}
                http_info = {}
            else:
                domain = input_value
            # Recursively clean all complex dictionary structures
            whois_info = json_safe(get_whois_info(domain))
            ip_info = json_safe(get_ip_info(domain))
            dns_info = json_safe(get_dns_records(domain))
            ssl_info = json_safe(get_ssl_info(domain))
            http_info = json_safe(get_http_status(domain))

            # Ensure ip_info and http_info are dicts before using .get()
            if not isinstance(ip_info, dict):
                ip_info = {}
            if not isinstance(http_info, dict):
                http_info = {}

            ip_address = ip_info.get("ip_address")
            server_location = get_server_location(ip_address) if ip_address else {}

            # 4️⃣ Save to Database
            if ip_info:
                success = "Domain information fetched successfully."
                print("SUCCESS:", success)
                domain_info = WebsiteDomainInfo.objects.create(
                    domain_name=domain,
                    dns_records=dns_info,  # Now safe
                    whois_info=whois_info,  # Now safe
                    ssl_info=ssl_info,  # Now safe
                    http_info=http_info,
                    ip_info=ip_info,
                    http_status_code=http_info.get("status_code"),
                    is_available=http_info.get("available", False),
                    # server_location=server_location,
                    server_location=json.dumps(server_location),
                )
                return redirect("website_domain_info_detail", domain_id=domain_info.id)

            else:
                error = "Could not retrieve IP information. Invalid domain."
                domains = WebsiteDomainInfo.objects.all()
                unique_countries = set()

                for d in WebsiteDomainInfo.objects.all():
                    if d.server_location:
                        try:
                            location = ast.literal_eval(d.server_location)
                            unique_countries.add(
                                location.get("country")
                                if location.get("country") != "None"
                                else "Unknown"
                            )
                        except Exception:
                            pass
                countries = list(unique_countries)

                print("ERROR:", error)
                return render(
                    request,
                    "index.html",
                    {
                        "domain_info": None,
                        "error": error,
                        "domains": domains,
                        "countries": countries,
                    },
                )
        except Exception as e:
            error = str(e)
            print("ERROR:", error)  # Debugging line

        return render(
            request,
            "index.html",
            {"domain_info": domain_info, "error": error, "success": success},
        )
    else:
        domains = WebsiteDomainInfo.objects.all()
        # Iterates through each object in the QuerySet and extracts the nested data
        unique_countries = set()

        for d in WebsiteDomainInfo.objects.all():
            if d.server_location:
                try:
                    location = ast.literal_eval(d.server_location)
                    unique_countries.add(
                        location.get("country")
                        if location.get("country") != "None"
                        else "Unknown"
                    )
                except Exception:
                    pass

        countries = list(unique_countries)
        # print("ALL DOMAINS:", domains)
        return render(
            request,
            "index.html",
            {
                "domains": domains,
                "error": None,
                "countries": countries,
                "https_status_codes": domains.values_list(
                    "http_status_code", flat=True
                ).distinct(),
            },
        )


def websit_domain_info_detail(request, domain_id):
    domain_info = get_object_or_404(WebsiteDomainInfo, pk=domain_id)
    success = "Domain information fetched successfully."
    return render(
        request,
        "website_domain_info_details.html",
        {"domain_info": domain_info, "success": success},
    )


def search_data(request):
    query = request.GET.get("q", "").strip().lower()
    results = []

    if query:
        results = WebsiteDomainInfo.objects.filter(domain_name=query)

    return render(request, "search_results.html", {"results": results, "query": query})


def apply_filters(request):
    country = request.GET.get("country", "").strip().upper()
    https_status_code = request.GET.get("https_status_code", "").strip()
    all_results = WebsiteDomainInfo.objects.all()
    error = None
    results = []
    if country and not https_status_code:
        for result in all_results:
            if result.server_location:
                try:
                    if country in result.server_location:
                        print(result.server_location, result.domain_name)
                        results.append(result)
                except Exception:
                    pass

    if https_status_code and not country:
        # Ensure results is a list so .append is valid in other branches
        results = list(all_results.filter(http_status_code=https_status_code))

    if country and https_status_code:
        for result in all_results:
            if result.server_location:
                try:
                    if (
                        country in result.server_location
                        and result.http_status_code == int(https_status_code)
                    ):
                        print(result.server_location, result.domain_name)
                        results.append(result)
                except Exception:
                    pass
                
    if not results:
        error = "No results found for the selected country."
    return render(request, "filter_result.html", {"results": results, "error": error})