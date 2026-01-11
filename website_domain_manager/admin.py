from django.contrib import admin
from .models import WebsiteDomainInfo

# Register your models here.
admin.site.register(WebsiteDomainInfo)
class WebsiteDomainInfoAdmin(admin.ModelAdmin):
    list_display = (
        "domain_name",
        "http_status_code",
        "is_available",
        "server_location",
        "created_at",
    )

    readonly_fields = (
        "dns_records",
        "whois_info",
        "ssl_info",
        "http_info",
        "ip_info",
        "created_at",
    )
    search_fields = ("domain_name",)
    list_filter = ("is_available", "http_status_code", "server_location")
   # date_hierarchy = "timestamp"
    ordering = ("-created_at",)
   # list_per_page = 20
    fieldsets = 20
   # fieldsets =
  