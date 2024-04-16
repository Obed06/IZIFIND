import socket
from django.utils import timezone
from django.conf import settings
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from .models import *



class CustomUserManager(BaseUserManager):

	def create_user(self, email, password=None, **extra_fields):
		if not email:
			raise ValueError('L\'adresse e-mail est obligatoire pour créer un utilisateur.')
		email = self.normalize_email(email)
		user = self.model(email=email, **extra_fields)
		user.set_password(password)
		user.save(using=self._db)
		return user

	def create_superuser(self, email, password=None, **extra_fields):
		user = self.create_user(email, password=password, **extra_fields)
		user.is_staff = True
		user.is_superuser = True
		user.is_admin = True
		user.save(using=self._db)
		return user 


class User(AbstractUser, PermissionsMixin):
	username = models.CharField(max_length=25, default="None")
	email = models.EmailField(unique=True)
	first_name = models.CharField(max_length=25)
	last_name = models.CharField(max_length=25)
	password = models.CharField(max_length=128)
	hostname = models.CharField(max_length=255, blank=True, null=True)

	is_active = models.BooleanField(default=True)
	is_admin = models.BooleanField(default=False)
	is_staff = models.BooleanField(default=False)
	is_superuser = models.BooleanField(default=False)

	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = ['password']

	objects = CustomUserManager()

	def __str__(self):
		return f'{self.first_name} {self.last_name}'

	def has_perm(self, perm, obj=None):
		return True

	def has_module_perms(self, app_label):
		return True


@receiver(post_save, sender=User)
def update_hostname(sender, instance, created, **kwargs):
	if created:
		try:
			instance.hostname = socket.gethostname()
			instance.save()
		except socket.error as e:
			print(f"Erreur lors de la récupération du hostname: {e}")



class TypeCategorie(models.Model):
    nom = models.CharField(max_length=100)

    def __str__(self):
        return self.nom


class Categorie(models.Model):
    type_categorie = models.ForeignKey(TypeCategorie, on_delete=models.CASCADE)
    categorie = models.CharField(max_length=100)

    def __str__(self):
        return self.categorie


class TypeNotification(models.Model):
    nom = models.CharField(max_length=100)

    def __str__(self):
        return self.nom


class TypeAbonnement(models.Model):
    nom = models.CharField(max_length=100)
    type_notification = models.ForeignKey(TypeNotification, on_delete=models.CASCADE)
    valeur = models.IntegerField()
    is_valid = models.BooleanField(default=False)
    who = models.ForeignKey(User, on_delete=models.CASCADE)
    when = models.DateTimeField(default=timezone.now)

    def update_when(self):
        if not self.when:
            try:
                self.when = timezone.now
                self.save()
            except Exception as e:
                print(f"Erreur lors de la récupération de la date: {e}")

    def __str__(self):
        return self.nom


class Souscription(models.Model):
    date = models.DateTimeField(default=timezone.now)
    type_abonnement = models.ForeignKey(TypeAbonnement, on_delete=models.CASCADE)
    is_valid = models.BooleanField(default=False)
    is_canceled = models.BooleanField(default=False)
    date_canceled = models.DateTimeField(null=True, blank=True)
    phone = models.CharField(max_length=15)

    def save(self, *args, **kwargs):
        if not self.id:
            self.start_date = timezone.now
            self.end_date = self.start_date + timezone.timedelta(days=self.type_abonnement.valeur)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Souscription n°{self.id} - Valide: {self.is_valid}"


class Lose(models.Model):
    date_declaration = models.DateTimeField(default=timezone.now)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    souscription = models.ForeignKey(Souscription, on_delete=models.CASCADE, default=1)
    info_categorie = models.ForeignKey(Categorie, on_delete=models.CASCADE, default=0)
    lieu = models.CharField(max_length=100)
    departement = models.CharField(max_length=100)
    commune = models.CharField(max_length=100)
    arrondissement = models.CharField(max_length=100)
    quartier = models.CharField(max_length=100)
    adresse = models.CharField(max_length=100)
    is_published = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_losed = models.BooleanField(default=False)
    is_stealed = models.BooleanField(default=False)
    is_client_valid = models.BooleanField(default=False)
    is_retrieve = models.BooleanField(default=False)

    def __str__(self):
        return self.info_categorie.categorie


class Find(models.Model):
    date_find = models.DateTimeField(default=timezone.now)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    souscription = models.ForeignKey(Souscription, on_delete=models.CASCADE, default=1)
    info_categorie = models.ForeignKey(Categorie, on_delete=models.CASCADE, default=0)
    lieu = models.CharField(max_length=100)
    departement = models.CharField(max_length=100)
    commune = models.CharField(max_length=100)
    arrondissement = models.CharField(max_length=100)
    quartier = models.CharField(max_length=100)
    adresse = models.CharField(max_length=100)
    is_valid = models.BooleanField(default=False)
    is_dropped = models.BooleanField(default=False)

    def __str__(self):
        return self.info_categorie.categorie


class Retrieve(models.Model):
    date_retrieve = models.DateTimeField(default=timezone.now)
    find = models.ForeignKey(Find, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    info_categorie = models.ForeignKey(Categorie, on_delete=models.CASCADE, default=0)
    info_temoins = models.TextField()
    photo = models.ImageField(upload_to="media/find/photo")
    document = models.FileField(upload_to="media/find/document")

    def __str__(self):
        return self.info_categorie.categorie


class Publish(models.Model):
    date_published = models.DateTimeField(default=timezone.now)
    retrieve = models.ForeignKey(Retrieve, on_delete=models.CASCADE)
    lose =  models.ForeignKey(Lose, on_delete=models.CASCADE)

    def __str__(self):
        return f"Perdu le: {self.date_published}"


class Temoignage(models.Model):
    date_temoignage = models.DateTimeField(default=timezone.now)
    object_retrieve = models.ForeignKey(Retrieve, on_delete=models.CASCADE)
    temoignage = models.TextField()

    def __str__(self):
        return self.temoignage


class Info(models.Model):
    adresse = models.CharField(max_length=100, default="Carrefour Calvaire, Fidjrossè")
    tel = models.CharField(max_length=100, default='+229 52 52 52 31')
    email = models.EmailField(default='contact@it-servicegroup.com')

    def __str__(self):
        return self.adresse


