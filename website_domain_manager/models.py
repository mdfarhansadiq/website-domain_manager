from django.db import models

# Create your models here.
class WebsiteDomainInfo(models.Model):
  domain_name = models.CharField(max_length=255, unique=True)

  # Aggregated data (single source of truth)
  dns_records = models.JSONField()
  whois_info = models.JSONField()
  ssl_info = models.JSONField()
  http_info = models.JSONField()
  ip_info = models.JSONField()

  # Derived / summary fields (useful for filtering & queries)
  http_status_code = models.IntegerField(null=True, blank=True)
  is_available = models.BooleanField(default=False)
  server_location = models.JSONField(null=True, blank=True)

  # Metadata
  # timestamp = models.DateTimeField()
  created_at = models.DateTimeField(auto_now_add=True)

  def __str__(self):
      return self.domain_name