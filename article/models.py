from django.db import models




class Item(models.Model):
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name


class Car(Item):
	make = models.CharField(max_length=100)
	model = models.CharField(max_length=100)
	year = models.PositiveIntegerField()
	color = models.CharField(max_length=100)
	plate_number = models.CharField(max_length=20)
	vin = models.CharField(max_length=17) # unique identification number
	last_seen_location = models.CharField(max_length=255)
	date_and_time_of_loss = models.DateTimeField()
	owner_name = models.CharField(max_length=255)
	owner_phone = models.CharField(max_length=20)
	owner_email = models.EmailField()
	documents = models.FileField(upload_to='car_documents/', blank=True)
	interior_description = models.TextField(blank=True)
	has_gps = models.BooleanField(default=False)
	is_find = models.BooleanField(default=False)
	found_location = models.CharField(max_length=255, blank=True, null=True)

	def __str__(self):
		return self.model


class Motorcycle(Item):
	make = models.CharField(max_length=255)
	model = models.CharField(max_length=255)
	year = models.PositiveIntegerField()
	color = models.CharField(max_length=255)
	plate_number = models.CharField(max_length=20)
	vin = models.CharField(max_length=17)
	last_seen_location = models.CharField(max_length=255)
	date_and_time_of_loss = models.DateTimeField()
	owner_name = models.CharField(max_length=255)
	owner_phone = models.CharField(max_length=20)
	owner_email = models.EmailField()
	documents = models.FileField(upload_to='motorcycle_documents/', blank=True)
	additional_details = models.TextField(blank=True)
	is_find = models.BooleanField(default=False)
	found_location = models.CharField(max_length=255, blank=True, null=True)

	def __str__(self):
		return self.model


class Key(Item):
	description = models.CharField(max_length=255)
	owner_name = models.CharField(max_length=255)
	owner_phone = models.CharField(max_length=20)
	owner_email = models.EmailField()
	last_seen_location = models.CharField(max_length=255)
	date_and_time_of_loss = models.DateTimeField()
	additional_details = models.TextField(blank=True)
	is_find = models.BooleanField(default=False)
	found_location = models.CharField(max_length=255, blank=True, null=True)

	def __str__(self):
		return self.owner_email


class USBKey(Item):
	description = models.CharField(max_length=255)
	last_seen_location = models.CharField(max_length=255)
	date_and_time_of_loss = models.DateTimeField()
	additional_details = models.TextField(blank=True)
	is_find = models.BooleanField(default=False)
	found_location = models.CharField(max_length=255, blank=True, null=True)

	def __str__(self):
		return self.description


class MobilePhone(Item):
	make = models.CharField(max_length=255)
	model = models.CharField(max_length=255)
	color = models.CharField(max_length=255)
	owner_name = models.CharField(max_length=255)
	owner_phone = models.CharField(max_length=20)
	owner_email = models.EmailField()
	last_seen_location = models.CharField(max_length=255)
	date_and_time_of_loss = models.DateTimeField()
	additional_details = models.TextField(blank=True)
	is_find = models.BooleanField(default=False)
	found_location = models.CharField(max_length=255, blank=True, null=True)

	def __str__(self):
		return self.owner_email


class Animal(Item):
	species = models.CharField(max_length=255)
	owner_name = models.CharField(max_length=255)
	owner_phone = models.CharField(max_length=20)
	owner_email = models.EmailField()
	last_seen_location = models.CharField(max_length=255)
	date_and_time_of_loss = models.DateTimeField()
	additional_details = models.TextField(blank=True)
	is_find = models.BooleanField(default=False)
	found_location = models.CharField(max_length=255, blank=True, null=True)

	def __str__(self):
		return self.owner_email


class Individual(Item):
	phone = models.CharField(max_length=20)
	email = models.EmailField()
	last_seen_location = models.CharField(max_length=255)
	date_and_time_of_loss = models.DateTimeField()
	additional_details = models.TextField(blank=True)
	is_find = models.BooleanField(default=False)
	found_location = models.CharField(max_length=255, blank=True, null=True)

	def __str__(self):
		return self.email

