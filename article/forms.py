from django import forms
from .models import Car, Motorcycle, Key, USBKey, MobilePhone, Animal, Individual




class CarForm(forms.ModelForm):
    class Meta:
        model = Car
        fields = [
            'make',
            'model',
            'year',
            'color',
            'plate_number',
            'vin',
            'last_seen_location',
            'date_and_time_of_loss',
            'owner_name',
            'owner_phone',
            'owner_email',
            'has_gps'
        ]


class MotorcycleForm(forms.ModelForm):
    class Meta:
        model = Motorcycle
        fields = [
            'make',
            'model',
            'year',
            'color',
            'plate_number',
            'vin',
            'last_seen_location',
            'date_and_time_of_loss',
            'owner_name',
            'owner_phone',
            'owner_email'
        ]


class KeyForm(forms.ModelForm):
    class Meta:
        model = Key
        fields = [
            'description',
            'owner_name',
            'owner_phone',
            'owner_email',
            'last_seen_location',
            'date_and_time_of_loss'
        ]


class USBKeyForm(forms.ModelForm):
    class Meta:
        model = USBKey
        fields = [
            'name',
            'description',
            'last_seen_location',
            'date_and_time_of_loss'
        ]


class MobilePhoneForm(forms.ModelForm):
    class Meta:
        model = MobilePhone
        fields = [
            'make',
            'model',
            'color',
            'owner_name',
            'owner_phone',
            'owner_email',
            'last_seen_location',
            'date_and_time_of_loss'
        ]


class AnimalForm(forms.ModelForm):
    class Meta:
        model = Animal
        fields = [
            'name',
            'species',
            'owner_name',
            'owner_phone',
            'owner_email',
            'last_seen_location',
            'date_and_time_of_loss'
        ]


class IndividualForm(forms.ModelForm):
    class Meta:
        model = Individual
        fields = [
            'name',
            'phone',
            'email',
            'last_seen_location',
            'date_and_time_of_loss'
        ]
