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


@api_view(['POST'])
def generate_password_and_send_email(request):
    if request.method == 'POST':
        email = request.data.get('email')  # Utilisez request.data pour obtenir les données du corps de la requête

        # Vérifier si l'e-mail existe dans la base de données
        try:
            User = get_user_model()
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "L'e-mail n'existe pas dans la base de données."}, status=400)

        # Générer un mot de passe aléatoire de 20 caractères
        password_length = 8 
        characters = string.ascii_letters + string.digits + string.punctuation
        generated_password = ''.join(secrets.choice(characters) for _ in range(password_length))

        # Générer un sel aléatoire (utiliser la fonction de Django)
        salt = None

        # Hacher le mot de passe généré avec l'algorithme SHA-2
        hashed_generated_password = make_password(generated_password, salt=salt)

        # Enregistrer le mot de passe haché comme ancien mot de passe pour l'utilisateur
        user.set_password(hashed_generated_password)
        user.save()

        # Obtenir l'heure actuelle
        current_time = timezone.now()

        # Calculer l'heure d'expiration (360 secondes plus tard)
        expiration_time = current_time + timezone.timedelta(seconds=420)

        # Construire le message de l'e-mail avec le mot de passe généré (non haché)
        subject = "Demande de réinitialisation de mot de passe"
        message = render_to_string('message_email.txt', {'generated_password': generated_password})

        from_email = "noreply@izifind.com"
        recipient_list = [email]

        # Envoyer l'e-mail
        send_mail(subject, message, from_email, recipient_list)

        response_data = {
            "message": "Un e-mail a été envoyé avec les instructions de réinitialisation.",
            "password": generated_password,
            "expiration_time": expiration_time,
        }

        return Response(response_data)

