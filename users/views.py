from django.shortcuts import render
from rest_framework.generics import CreateAPIView
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from .serializers import RegisterUserSerializer



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
