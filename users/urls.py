from django.urls import path
from .views import (
	RegisterUserView,
	login_view,
	reset_password_email
)

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('login/', login_view, name='login'),
    path('reset_password_email/', reset_password_email, name='reset_password_email')
]
