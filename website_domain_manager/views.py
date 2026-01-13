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
import requests
import website_domain_manager.helper_function as helper_function
from .models import WebsiteDomainInfo


# Create your views here.
def index(request):
    domains = WebsiteDomainInfo.objects.all()
    return render(request, "index.html", {"domains": domains})

def fetch_info(request):
    domain_info = None
    error = None
    success = None
    domain = None

    if request.method == "POST":
        input_value = request.POST.get("domain_name", "").strip().lower()
        domains = WebsiteDomainInfo.objects.all()

        # 2️⃣ Check if domain already exists (single query)
        if helper_function.is_ip_address(input_value):
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
                {
                    "domain_info": existing,
                    "error": None,
                    "success": success,
                    "https_status_codes": domains.values_list(
                        "http_status_code", flat=True
                    )
                    .exclude(http_status_code__isnull=True)
                    .exclude(http_status_code=None)
                    .distinct()
                    .order_by("http_status_code"),
                },
            )

        try:
            # 1️⃣ Validate input
            if not helper_function.is_valid_domain(input_value) and not helper_function.is_ip_address(input_value):
                error = "Invalid domain name or IP address."
                domains = WebsiteDomainInfo.objects.all()
                countries = (
                    WebsiteDomainInfo.objects.values_list(
                        "server_location__country", flat=True
                    )
                    .exclude(server_location__country__isnull=True)
                    .exclude(server_location__country=None)
                    .distinct()
                )
                print("ERROR:", error)
                return render(
                    request,
                    "index.html",
                    {
                        "domain_info": None,
                        "error": error,
                        "domains": domains,
                        "countries": countries,
                        "https_status_codes": domains.values_list(
                            "http_status_code", flat=True
                        )
                        .exclude(http_status_code__isnull=True)
                        .exclude(http_status_code=None)
                        .distinct()
                        .order_by("http_status_code"),
                    },
                )

            # 3️⃣ Fetch all information concurrently
            # If it's an IP, we can't get WHOIS or DNS directly from it
            if helper_function.is_ip_address(input_value):
                domain = input_value  # Treat IP as the domain for fetching
                try:
                    hostname, _, _ = helper_function.socket.gethostbyaddr(input_value)
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
            whois_info = helper_function.json_safe(helper_function.get_whois_info(domain))
            ip_info = helper_function.json_safe(helper_function.get_ip_info(domain))
            dns_info = helper_function.json_safe(helper_function.get_dns_records(domain))
            ssl_info = helper_function.json_safe(helper_function.get_ssl_info(domain))
            http_info = helper_function.json_safe(helper_function.get_http_status(domain))
            # Ensure ip_info and http_info are dicts before using .get()
            if not isinstance(ip_info, dict):
                ip_info = {}
            if not isinstance(http_info, dict):
                http_info = {}

            ip_address = ip_info.get("ip_address")
            server_location = helper_function.get_server_location(ip_address) if ip_address else {}

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
                    server_location=helper_function.json_safe(server_location),
                )
                return redirect("website_domain_info_detail", domain_id=domain_info.id)

            else:
                error = "Could not retrieve IP information. Invalid domain."
                domains = WebsiteDomainInfo.objects.all()
                countries = (
                    WebsiteDomainInfo.objects.values_list(
                        "server_location__country", flat=True
                    )
                    .exclude(server_location__country__isnull=True)
                    .exclude(server_location__country=None)
                    .distinct()
                )

                print("ERROR:", error)
                return render(
                    request,
                    "index.html",
                    {
                        "domain_info": None,
                        "error": error,
                        "domains": domains,
                        "countries": countries,
                        "https_status_codes": domains.values_list(
                            "http_status_code", flat=True
                        )
                        .exclude(http_status_code__isnull=True)
                        .exclude(http_status_code=None)
                        .distinct()
                        .order_by("http_status_code"),
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
        countries = (
            WebsiteDomainInfo.objects.values_list("server_location__country", flat=True)
            .exclude(server_location__country__isnull=True)
            .exclude(server_location__country=None)
            .distinct()
        )
        # Iterates through each object in the QuerySet and extracts the nested data
        print("ALL DOMAINS:", domains)
        return render(
            request,
            "index.html",
            {
                "domains": domains,
                "error": None,
                "countries": countries,
                "https_status_codes": domains.values_list("http_status_code", flat=True)
                .exclude(http_status_code__isnull=True)
                .exclude(http_status_code=None)
                .distinct()
                .order_by("http_status_code"),
            },
        )


def edit_domain_info(request, domain_id):
    domain_info = get_object_or_404(WebsiteDomainInfo, pk=domain_id)
    error = None
    success = None

    if request.method == "POST":
        # Example: Allow editing of the domain_name only
        new_domain_name = request.POST.get("domain_name", "").strip().lower()

        if helper_function.is_valid_domain(new_domain_name):
            domain_info.domain_name = new_domain_name
            domain_info.save()
            success = "Domain information updated successfully."
            return redirect("index")
        else:
            error = "Invalid domain name."

    return render(
        request,
        "edit_domain_info.html",
        {"domain_info": domain_info, "error": error, "success": success},
    )


def delete_domain_info(request, domain_id):
    domain_info = get_object_or_404(WebsiteDomainInfo, pk=domain_id)
    domain_info.delete()
    return redirect("index")


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
    error = None
    results = []
    country = request.GET.get("country", "").strip().upper()
    https_status_code = request.GET.get("https_status_code", "").strip()
    all_results = WebsiteDomainInfo.objects.filter(
        server_location__country=country, http_status_code=https_status_code
    )

    results = list(all_results)
    if not results:
        error = "No results found for the selected country."
    return render(request, "filter_result.html", {"results": results, "error": error})