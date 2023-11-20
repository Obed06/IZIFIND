from django.urls import path
from .views import (
	RegisterUserView,
	login, sign_up,
	generate_password_and_send_email,
)

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'), # api inscription
    path('password/reset/', generate_password_and_send_email, name='password_reset'), # api mot de passe oublier

    # TESTS
    path('test_connect/', login, name="test_connect"),
    path('test_sign_up/', sign_up, name="test_sign_up"),
]
