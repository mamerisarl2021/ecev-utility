from django.urls import include, path
from . import views


# existing serializer, viewset, router registrations code
urlpatterns = [ 
    path('generate', views.generate_cev, name='index'),
    path('appose-cev', views.appose_cev, name='index'),
    path('checkrevocation/<str:cn>', views.revoked.as_view()),
    path('Pdfs/<str:file_path>', views.stream_http_download, name='index'),
    path('Cevs/<str:file_path>', views.stream_cev_http_download, name='index'),
    path('read-cev/<str:file_path>', views.stream_cev_http_read, name='index'),
    path('verify-signature', views.verifiysignature, name='index'),
    path('verify-data', views.verify_data, name='index'),
    # path('convert', views.converttopng, name='index'),
]
