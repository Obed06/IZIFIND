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
from django.conf import settings

from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import api_view, action
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.views import APIView

import requests

from .serializers import *
from .models import *




class RegisterUserView(CreateAPIView):
	queryset = get_user_model().objects.all()
	permission_classes = (AllowAny,)
	serializer_class = RegisterUserSerializer


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


class MessageViewSet(viewsets.ModelViewSet):
	queryset = Message.objects.all()
	serializer_class = MessageSerializer

	@action(detail=False, methods=['get'])
	def inbox(self, request):
		# Récupérer la boîte de réception de l'utilisateur connecté
		user = self.request.user
		messages = Message.objects.filter(receiver=user)
		serializer = MessageSerializer(messages, many=True)
		return Response(serializer.data)

	@action(detail=True, methods=['post'])
	def send_message(self, request, pk=None):
		# Envoyer un message à un utilisateur spécifique
		sender = self.request.user
		receiver = self.get_object().receiver
		content = request.data.get('content', '')

		if content:
			Message.objects.create(sender=sender, receiver=receiver, content=content)
			return Response({'success': True, 'message': 'Message envoyé avec succès'}, status=status.HTTP_200_OK)
		else:
			return Response({'success': False, 'message': 'Le contenu du message ne peut pas être vide'}, status=status.HTTP_400_BAD_REQUEST)


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

