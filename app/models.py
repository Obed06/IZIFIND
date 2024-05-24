import socket
from django.utils import timezone
from django.conf import settings
from django.db import models
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.contrib.auth.signals import user_logged_in
from django.core.validators import MinValueValidator, MaxValueValidator
from .models import *




class TypeCategorie(models.Model):
	nom = models.CharField(max_length=100)

	def __str__(self):
		return self.nom


class Categorie(models.Model):
	type_categorie = models.ForeignKey(TypeCategorie, on_delete=models.CASCADE)
	categorie = models.CharField(max_length=100)

	def __str__(self):
		return self.categorie


class Lose(models.Model):
	date_declaration = models.DateTimeField(default=timezone.now)
	lieu = models.CharField(max_length=100, blank=True, null=True)
	categorie = models.ForeignKey(Categorie, on_delete=models.CASCADE)
	type_categorie = models.ForeignKey(TypeCategorie, on_delete=models.CASCADE, default=1)
	object_value = models.DecimalField(max_digits=9, decimal_places=3, default=0.0)
	reward_value = models.IntegerField(default=False,  blank=True, null=True)
	
	language_speak = models.CharField(max_length=100, blank=True)
	gender = models.CharField(max_length=100, blank=True)
	age = models.CharField(max_length=100, blank=True)
	tail = models.DecimalField(max_digits=3, decimal_places=2, blank=True, default=0.0)
	skin_color = models.CharField(max_length=100, blank=True)
	couleur = models.CharField(max_length=100, blank=True)
	marque = models.CharField(max_length=100, blank=True)
	immatricul = models.CharField(max_length=100, blank=True)
	ram = models.CharField(max_length=100, blank=True)
	rom = models.CharField(max_length=100, blank=True)
	image = models.ImageField(upload_to="media/lose/photo", blank=True, null=True)
	
	is_reward = models.BooleanField(default=False)
	is_dropped = models.BooleanField(default=False)
	is_published = models.BooleanField(default=False)
	is_verified = models.BooleanField(default=False)
	is_losed = models.BooleanField(default=False)
	is_stealed = models.BooleanField(default=False)
	is_client_valid = models.BooleanField(default=False) #algo pour mettre à jour la validité de l'abonnement du client
	is_retrieve = models.BooleanField(default=False) #algo pour mettre à jour le statut de "is_retrieve"

	def __str__(self):
		return self.categorie.categorie


class Find(models.Model):
	date_find = models.DateTimeField(default=timezone.now)
	nom = models.CharField(max_length=100, blank=True, null=True)
	prenom = models.CharField(max_length=100, blank=True, null=True)
	tel = models.CharField(max_length=100, blank=True, null=True)
	email = models.EmailField(unique=True, blank=True, null=True)
	lieu = models.CharField(max_length=100, blank=True, null=True)
	categorie = models.ForeignKey(Categorie, on_delete=models.CASCADE)
	is_valid = models.BooleanField(default=False)
	is_dropped = models.BooleanField(default=False)
	is_subscribe = models.BooleanField(default=False)
	is_published = models.BooleanField(default=False)
	is_retrieve = models.BooleanField(default=False)

	def __str__(self):
		return self.categorie.categorie


class Retrieve(models.Model):
	date_retrieve = models.DateTimeField(default=timezone.now)
	find = models.ForeignKey(Find, on_delete=models.CASCADE)
	info_temoins = models.TextField()
	photo = models.ImageField(upload_to="media/find/photo", blank=True, null=True)
	document = models.FileField(upload_to="media/find/document", blank=True, null=True)

	def __str__(self):
		return self.info_categorie.categorie


class Publish(models.Model):
	date_published = models.DateTimeField(default=timezone.now)
	retrieve = models.OneToOneField(Retrieve, on_delete=models.CASCADE)
	is_publish = models.BooleanField(default=False)

	def __str__(self):
		return f"Perdu le: {self.date_published}"


class Info(models.Model):
	adresse = models.CharField(max_length=100, default="Carrefour Calvaire, Fidjrossè")
	tel = models.CharField(max_length=100, default='+229 52 52 52 31')
	email = models.EmailField(default='contact@it-servicegroup.com')
	pourcentage = models.DecimalField(decimal_places=2, max_digits=5, blank=True, default=0.0)
	valeur_reel = models.PositiveIntegerField(blank=True, default=0)

	def __str__(self):
		return self.adresse

	def save(self, *args, **kwargs):
		self.pourcentage /= 100
		super(Info, self).save(*args, **kwargs)


class TypeNotification(models.Model):
	nom = models.CharField(max_length=100)

	def __str__(self):
		return self.nom


class TypeAbonnement(models.Model):
	nom = models.CharField(max_length=100)
	type_notification = models.ForeignKey(TypeNotification, on_delete=models.CASCADE)
	valeur = models.DecimalField(max_digits=9, decimal_places=3)
	nombre_de_jours = models.PositiveIntegerField(default=0)
	is_active = models.BooleanField(default=False)

	def __str__(self):
		return self.nom


class CustomUserManager(BaseUserManager):

	def validate_email_or_phone_unique(self, value):
		# Vérifier si une adresse e-mail ou un numéro de téléphone existe déjà dans la base de données
		if self.model.objects.filter(email_or_phone=value).exists():
			raise ValidationError(
				_('Un utilisateur avec cet email ou numéro de téléphone existe déjà.'),
				params={'value': value},
			)

	def create_user(self, email_or_phone, password=None, **extra_fields):
		if not email_or_phone:
			raise ValueError('L\'adresse e-mail ou le numéro de téléphone est obligatoire pour créer un utilisateur.')

		if '@' in email_or_phone:
			email = self.normalize_email(email_or_phone)
			extra_fields.setdefault('email_or_phone', email)
		else:
			extra_fields.setdefault('email_or_phone', email_or_phone)

		self.validate_email_or_phone_unique(extra_fields['email_or_phone'])

		user = self.model(**extra_fields)
		user.set_password(password)
		user.save(using=self._db)
		return user

	def create_superuser(self, email_or_phone, password=None, **extra_fields):
		extra_fields.setdefault('is_staff', True)
		extra_fields.setdefault('is_superuser', True)
		extra_fields.setdefault('is_admin', True)
		return self.create_user(email_or_phone, password=password, **extra_fields)


class User(AbstractUser, PermissionsMixin):
	username = None
	email_or_phone = models.CharField(max_length=100, unique=True)
	password = models.CharField(max_length=128)
	hostname = models.CharField(max_length=255, blank=True, null=True)
	create_date = models.DateTimeField(default=timezone.now)
	last_login_date = models.DateTimeField(null=True, blank=True)
	last_modify_date = models.DateTimeField(null=True, blank=True)
	deactivate_date = models.DateTimeField(null=True, blank=True)
	is_active = models.BooleanField(default=True)
	is_admin = models.BooleanField(default=False)
	is_staff = models.BooleanField(default=False)
	is_superuser = models.BooleanField(default=False)

	USERNAME_FIELD = "email_or_phone"
	REQUIRED_FIELDS = []

	objects = CustomUserManager()

	def __str__(self):
		return self.email_or_phone


@receiver(post_save, sender=User)
def update_hostname(sender, instance, created, **kwargs):
	if created:
		try:
			instance.hostname = socket.gethostname()
			instance.save()
		except socket.error as e:
			print(f"Erreur lors de la récupération du hostname: {e}")


@receiver(user_logged_in, sender=User)
def update_last_login(sender, user, **kwargs):
    user.last_login_date = timezone.now()
    user.save()


@receiver(pre_save, sender=User)
def update_last_modify(sender, instance, **kwargs):
    instance.last_modify_date = timezone.now()


@receiver(post_save, sender=User)
def update_deactivate_date(sender, instance, **kwargs):
    if not instance.is_active and instance.deactivate_date is None:
        instance.deactivate_date = timezone.now()
        instance.save()


class Temoignage(models.Model):
	user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
	date_temoignage = models.DateTimeField(default=timezone.now)
	temoignage = models.TextField()

	def __str__(self):
		return self.temoignage


class Souscription(models.Model):
	date = models.DateTimeField(default=timezone.now, blank=True)
	type_abonnement = models.ForeignKey(TypeAbonnement, on_delete=models.CASCADE)
	user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
	is_valid = models.BooleanField(default=False, blank=True)
	is_canceled = models.BooleanField(default=False, blank=True)
	date_canceled = models.DateTimeField(null=True, blank=True)
	start_date = models.DateTimeField(null=True, blank=True)
	end_date = models.DateTimeField(null=True, blank=True)

	def __str__(self):
		return self.date


class Notification(models.Model):
	date = models.DateTimeField(default=timezone.now)
	souscription = models.ForeignKey(Souscription, on_delete=models.CASCADE)
	retrieve = models.ForeignKey(Retrieve, on_delete=models.CASCADE, default=1)
	publish = models.ForeignKey(Publish, on_delete=models.CASCADE)

	def __str__(self):
		return f"Notification du {self.date}"


class Payment(models.Model):
	date = models.DateTimeField(default=timezone.now)
	montant_operation = models.DecimalField(max_digits=10, decimal_places=3, blank=True) # algo pour le calcul du montant de toutes les opérations
	montant_remis = models.DecimalField(max_digits=10, decimal_places=3, blank=True)
	relicat = models.DecimalField(max_digits=10, decimal_places=3, blank=True)


"""
UNE NOUVELLE SECTION DANS LA DOCUMENTATION DE IZIFIND
------------------------------------------------------
	Recherche faite texte en voix et recto-verso. Autrement dit, "text to voice AND voice to text"
	La langue utilisée est le FRANÇAIS ensuite l'ANGLAIS et après on ajoutera une LANGUE LOCALE.
------------------------------------------------------
"""