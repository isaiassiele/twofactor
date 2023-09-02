from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .import views
from django.contrib.auth import views as auth_view





urlpatterns = [

    path('register/', views.register_view, name='register'),
    path('verify-otp/', views.verify_registration_otp_view, name='verify_registration_otp'),
    path('login/', views.login_view, name='login'),
    path('second-factor/', views.second_factor_view, name='second_factor'),
    path('', views.dashboard_view, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),

    # path('logout/',auth_view.LogoutView.as_view()),
 
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)