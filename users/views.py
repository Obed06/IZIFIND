from django.shortcuts import render, redirect
from rest_framework.generics import CreateAPIView
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from .serializers import RegisterUserSerializer

from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetConfirmView

from django.urls import reverse
from django.views import View
from rest_framework.decorators import api_view
import string
import secrets
from django.contrib.auth.hashers import make_password
from django.utils import timezone

from django.contrib.auth import authenticate, login




class RegisterUserView(CreateAPIView):
	queryset = get_user_model().objects.all()
	permission_classes = (AllowAny,)
	serializer_class = RegisterUserSerializer


def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Appel à TokenObtainPairView pour obtenir le token d'accès
        response = TokenObtainPairView.as_view()(request)
        return response

    return render(request, 'login.html')


def sign_up(request):
	return render(request, 'register.html')

