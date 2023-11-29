from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin




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
	username = None
	email = models.EmailField(unique=True)
	first_name = models.CharField(max_length=25)
	last_name = models.CharField(max_length=25)
	password = models.CharField(max_length=128)

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


class Message(models.Model):
	sender = models.ForeignKey(get_user_model(), related_name='sent_messages', on_delete=models.CASCADE)
	receiver = models.ForeignKey(get_user_model(), related_name='received_messages', on_delete=models.CASCADE)
	content = models.TextField()
	timestamp = models.DateTimeField(auto_now_add=True)
	is_read = models.BooleanField(default=False)

	def __str__(self):
		return f"De {self.sender} à {self.receiver}"