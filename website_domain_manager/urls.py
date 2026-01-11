from django.urls import path
from . import views

# app_name = 'website_domain_manager'
urlpatterns = [
    path('', views.fetch_info, name='index'),
    path('fetch_info/', views.fetch_info, name='fetch_info'),
    path('domain/<int:domain_id>/', views.websit_domain_info_detail, name='website_domain_info_detail'),
    path('search/', views.search_data, name='search'),
    path('apply_filters/', views.apply_filters, name='apply_filters'),
]