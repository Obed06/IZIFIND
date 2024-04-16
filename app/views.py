from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail, BadHeaderError
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render, get_object_or_404
from django.contrib import messages
from django.contrib.auth.forms import SetPasswordForm
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view, action
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.views import APIView
import requests
from django.db.models import Q
from decouple import config
from .serializers import *
from .models import *



class RegisterUserView(CreateAPIView):
	queryset = get_user_model().objects.all()
	permission_classes = (AllowAny,)
	serializer_class = RegisterUserSerializer

	def perform_create(self, serializer):
		user = serializer.save()
		self.send_registration_email(user)

	def send_registration_email(self, user):
		subject = 'Bienvenue sur IziFind'
		html_message = render_to_string('authentication/registration_email.html', {'user': user})
		plain_message = strip_tags(html_message)
		from_email = 'leonardovodouhe06@gmail.com'
		to_email = [user.email]
		send_mail(subject, plain_message, from_email, to_email, html_message=html_message)

	def create(self, request, *args, **kwargs):
		response = super().create(request, *args, **kwargs)
		return render(request, 'authentication/200_registration_email.html', status=200)


class UserViewSet(viewsets.ModelViewSet):
	queryset = get_user_model().objects.all()
	serializer_class = RegisterUserSerializer

	def retrieve(self, request, *args, **kwargs):
		user_instance = self.get_object()
		serializer = self.get_serializer(user_instance)
		return Response(serializer.data)

	def update(self, request, *args, **kwargs):
		user_instance = self.get_object()
		serializer = self.get_serializer(user_instance, data=request.data, partial=True)
		serializer.is_valid(raise_exception=True)
		serializer.save()
		return Response(serializer.data)


class SendNotificationViewSet(viewsets.GenericViewSet):
	permission_classes = (AllowAny,)
	serializer_class = SendNotificationSerializer

	def create(self, request, *args, **kwargs):
		try:
			serializer = self.get_serializer(data=request.data)
			serializer.is_valid(raise_exception=True)

			subject = serializer.validated_data.get('subject', 'Sujet de la notification')
			message = serializer.validated_data.get('message', 'Corps du message de la notification')

			from_email = settings.EMAIL_FROM

			# Récupérer la liste de tous les utilisateurs
			all_users = get_user_model().objects.all()

			# Envoyer la notification à chaque utilisateur
			for user in all_users:
				email_subject = f'Notification: {subject}'
				email_message = f'Bonjour {user.email},\n\n{message}'

				send_mail(email_subject, email_message, from_email, [user.email], fail_silently=False)

			return Response({'message': 'Notifications envoyées avec succès à tous les utilisateurs.'}, status=status.HTTP_200_OK)

		except (DjangoValidationError, DRFValidationError) as e:
			return Response({'message': 'Erreur lors de la validation des données.', 'errors': e.detail}, status=status.HTTP_400_BAD_REQUEST)
		except BadHeaderError:
			return Response({'message': 'Erreur lors de l\'envoi de l\'e-mail.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
		except Exception as e:
			return Response({'message': f'Erreur inattendue: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




@api_view(['DELETE'])
def delete_user(request, user_id):
	try:
		user = get_user_model().objects.get(pk=user_id)
		user.delete()
		return Response({'message': f'User with ID {user_id} has been deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
	except get_user_model().DoesNotExist:
		return Response({'message': f'User with ID {user_id} does not exist.'}, status=status.HTTP_404_NOT_FOUND)
	except Exception as e:
		return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
def login_view(request):
    if request.method == 'POST':
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            return render(request, 'authentication/authentication-login.html', {'error_message': "Identifiant ou mot de passe incorrect."})
    else:
        # Si la méthode est GET, renvoyer simplement le formulaire de login
        return render(request, 'authentication/authentication-login.html')


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
		html_message = render_to_string('authentication/reset_message.html', {'reset_url':reset_url, 'email':email})
		
		from_email = 'leonardovodouhe06@gmail.com'
		to_email = [user.email]

		try:
			send_mail(subject, '', from_email, to_email, html_message=html_message, fail_silently=False)
			# return Response({'message': 'Un e-mail de réinitialisation de mot de passe a été envoyé.'}, status=status.HTTP_200_OK)
			return render(request, 'authentication/200_reset_password_email_sent.html')
		except BadHeaderError:
			# return Response({'message': 'Erreur lors de l\'envoi de l\'e-mail.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
			return render(request, 'authentication/500_reset_password_email_sent.html')
		except (DjangoValidationError, DRFValidationError) as e:
			# return Response({'message': 'Erreur lors de la validation des données.', 'errors': e.detail}, status=status.HTTP_400_BAD_REQUEST)
			return render(request, 'authentication/400_reset_password_email_sent.html')
	else:
		return Response({'message': 'Méthode non autorisée.'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


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
				return redirect('page_login')
		else:
			form = SetPasswordForm(user)

		return render(request, 'authentication/reset_password_confirm.html', {'form': form, 'uidb64': uidb64, 'token': token})

	else:
		messages.error(request, 'Ce lien de réinitialisation de mot de passe est invalide.')
		return redirect('page_password_email')


@api_view(['POST'])
def xend_email(request):
    try:
        # Récupérer les données du formulaire
        nom = request.data.get('nom')
        email = request.data.get('email')
        message = request.data.get('message')

        # Validation des données
        if not nom or not email or not message:
            raise DjangoValidationError("Tous les champs sont obligatoires.")

        # Paramètres de l'e-mail
        subject = 'Nouveau message de {}'.format(nom)
        from_email = email
        to_email = ['leonardovodouhe06@gmail.com']

        # Envoyer l'email
        send_mail(
            subject,
            message,
            from_email,
            to_email,
            fail_silently=False,
        )

        # Réponse de succès
        #return Response({'message': 'Email envoyé avec succès.'})
        #messages.success(request, 'Email envoyé avec succès.')
        return redirect('home')

    except DjangoValidationError as e:  # Correction ici
        # En cas d'erreur de validation, retourner les détails de l'erreur
        return Response({'error': str(e)}, status=400)

    except Exception as e:
        # En cas d'autres erreurs, retourner un message d'erreur générique
        return Response({'error': 'Une erreur est survenue lors de l\'envoi de l\'email.'}, status=500)



class LoseViewSet(viewsets.ModelViewSet):
    queryset = Lose.objects.all()
    serializer_class = LoseSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=201)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=204)


class FindViewSet(viewsets.ModelViewSet):
    queryset = Find.objects.all()
    serializer_class = FindSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=201)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=204)



def page_register(request):
	return render(request, 'authentication/authentication-register.html')


def page_login(request):
	return render(request, 'authentication/authentication-login.html')


def page_password_email(request):
	return render(request, 'authentication/reset_password_email.html')


def home(request):
	info = Info.objects.first()
	return render(request, 'home/index.html', {"objet":info})


def lose(request):
	info = Info.objects.first()
	return render(request, 'home/perdu.html', {"objet":info})


def find(request):
	info = Info.objects.first()
	return render(request, 'home/trouve.html', {"objet":info})
