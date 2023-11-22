from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail, BadHeaderError
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.contrib import messages
from django.contrib.auth.forms import SetPasswordForm

from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.exceptions import ValidationError as DRFValidationError

from .serializers import RegisterUserSerializer
from .models import User




class RegisterUserView(CreateAPIView):
	queryset = get_user_model().objects.all()
	permission_classes = (AllowAny,)
	serializer_class = RegisterUserSerializer


@api_view(['POST'])
def login_view(request):
	if request.method == 'POST':
		email = request.data.get('email')
		password = request.data.get('password')

		user = authenticate(request, email=email, password=password)

		if user is not None:
			login(request, user)
			return Response({'message': "Connexion réussie."}, status=status.HTTP_200_OK)
		else:
			return Response({'message': "Identifiant ou mot de passe incorrect."}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
def reset_password_email(request):
	if request.method == 'POST':
		email = request.data.get('email')

		try:
			user = User.objects.get(email=email)
		except User.DoesNotExist:
			return Response({'message': 'Utilisateur non trouvé.'}, status=status.HTTP_404_NOT_FOUND)

		token = default_token_generator.make_token(user)
		uri = urlsafe_base64_encode(force_bytes(user.pk))

		# Construire l'URL complète
		# reset_url = f'http://localhost:8000/reset-password/{uri}/{token}'
		reset_url = request.build_absolute_uri(reverse('reset_password_confirm', kwargs={'uidb64': uri, 'token': token}))

		# Envoyer l'e-mail avec le lien de réinitialisation de mot de passe
		subject = 'Réinitialisation de mot de passe'
		message = f'Bonjour {email},\n\nVous avez demandé la réinitialisation de votre mot de passe.\n\
Si c\'est le cas, cliquez sur le lien suivant pour réinitialiser votre mot de passe : {reset_url}. \n\nAssurez-vous de changer ce mot de passe dès que possible.\n\n\
Merci,\n\
L\'équipe d\'IZIFIND'
		
		from_email = 'leonardovodouhe06@gmail.com'
		to_email = [user.email]

		try:
			send_mail(subject, message, from_email, to_email, fail_silently=False)
			return Response({'message': 'Un e-mail de réinitialisation de mot de passe a été envoyé.'}, status=status.HTTP_200_OK)
		except BadHeaderError:
			return Response({'message': 'Erreur lors de l\'envoi de l\'e-mail.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
		except (DjangoValidationError, DRFValidationError) as e:
			return Response({'message': 'Erreur lors de la validation des données.', 'errors': e.detail}, status=status.HTTP_400_BAD_REQUEST)


def reset_password_confirm(request, uidb64, token):
	try:
		uid = force_str(urlsafe_base64_decode(uidb64))
		user = get_user_model().objects.get(pk=uid)
	except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
		user = None

	if user is not None and default_token_generator.check_token(user, token):
		if request.method == 'POST':
			form = SetPasswordForm(user, request.POST)
			if form.is_valid():
				form.save()
				messages.success(request, 'Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous connecter avec votre nouveau mot de passe.')
				return redirect('login')
		else:
			form = SetPasswordForm(user)

		return render(request, 'reset_password_confirm.html', {'form': form})
	else:
		messages.error(request, 'Ce lien de réinitialisation de mot de passe est invalide.')
		return redirect('login')
