from django.urls import path
from .views import (
	RegisterUserView,
	login, sign_up,
)

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'), # api inscription

    # TESTS
    path('test_connect/', login, name="test_connect"),
    path('test_sign_up/', sign_up, name="test_sign_up"),
]
