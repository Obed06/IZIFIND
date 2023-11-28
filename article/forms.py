from django import forms
from .models import Item, Car, Motorcycle, Key, USBKey, MobilePhone, Animal, Individual




class ItemForm(forms.ModelForm):
    class Meta:
        model = Item
        fields = '__all__'


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
            'has_gps',
            'is_find',
            'found_location',
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
            'owner_email',
            'is_find',
            'found_location',
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
            'date_and_time_of_loss',
            'is_find',
            'found_location',
        ]


class USBKeyForm(forms.ModelForm):
    class Meta:
        model = USBKey
        fields = [
            'name',
            'description',
            'last_seen_location',
            'date_and_time_of_loss',
            'is_find',
            'found_location',
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
            'date_and_time_of_loss',
            'is_find',
            'found_location',
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
            'date_and_time_of_loss',
            'is_find',
            'found_location',
        ]


class IndividualForm(forms.ModelForm):
    class Meta:
        model = Individual
        fields = [
            'name',
            'phone',
            'email',
            'last_seen_location',
            'date_and_time_of_loss',
            'is_find',
            'found_location',
        ]
