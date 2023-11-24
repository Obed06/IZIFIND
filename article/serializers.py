from rest_framework import serializers
from .models import Car, Motorcycle, Key, USBKey, MobilePhone, Animal, Individual




class CarSerializer(serializers.ModelSerializer):
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
            'share_location'
        ]


class MotorcycleSerializer(serializers.ModelSerializer):
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
            'share_location'
        ]


class KeySerializer(serializers.ModelSerializer):
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
            'share_location'
        ]


class USBKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = USBKey
        fields = [
            'name',
            'description',
            'last_seen_location',
            'date_and_time_of_loss',
            'is_find',
            'share_location'
        ]


class MobilePhoneSerializer(serializers.ModelSerializer):
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
            'share_location'
        ]


class AnimalSerializer(serializers.ModelSerializer):
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
            'share_location'
        ]


class IndividualSerializer(serializers.ModelSerializer):
    class Meta:
        model = Individual
        fields = [
            'name',
            'phone',
            'email',
            'last_seen_location',
            'date_and_time_of_loss',
            'is_find',
            'share_location'
        ]
