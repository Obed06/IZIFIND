from django.contrib import admin
from django.urls import path, include
from dj_rest_auth.views import (
    LoginView, LogoutView, PasswordChangeView, PasswordResetView
)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls')),
    path('rest-auth/', include('rest_auth.urls')),
    path('rest-auth/registration/', include('rest_auth.registration.urls')),

    # LES APIS A TESTER
    path('auth/login/', LoginView.as_view(), name='rest_login'),
    path('auth/logout/', LogoutView.as_view(), name='rest_logout'),
    path('auth/password/change/', PasswordChangeView.as_view(), name='rest_password_change'),
    path('auth/password/reset/', PasswordResetView.as_view(), name='rest_password_reset'),
]
