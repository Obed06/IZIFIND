from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from rest_framework import serializers
from .models import *




User = get_user_model()

class RegisterUserSerializer(serializers.ModelSerializer):
    email_or_phone = serializers.CharField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(write_only=True, required=True, validators=[validate_password], style={'input_type':'password'})
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('email_or_phone', 'password', 'first_name', 'last_name')

    def validate(self, data):
        email_or_phone = data.get('email_or_phone')
        if '@' in email_or_phone:
            data['email_or_phone'] = email_or_phone
        else:
            data['email_or_phone'] = email_or_phone
        return data

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user


class SendNotificationSerializer(serializers.Serializer):
    subject = serializers.CharField(max_length=255, required=True)
    message = serializers.CharField(required=True, style={"input_type": "textarea"})


class LoseSerializer(serializers.ModelSerializer):
    categorie_display = serializers.CharField(source='get_categorie_display', read_only=True)
    voler_display = serializers.CharField(source='get_voler_display', read_only=True)

    class Meta:
        model = Lose
        fields = '__all__'


class FindSerializer(serializers.ModelSerializer):

    class Meta:
        model = Find
        fields = '__all__'


class TypeCategorieSerializer(serializers.ModelSerializer):
    class Meta:
        model = TypeCategorie
        fields = ['id', 'nom']

class CategorieSerializer(serializers.ModelSerializer):
    class Meta:
        model = Categorie
        fields = ['id', 'type_categorie', 'categorie']

    def to_representation(self, instance):
        """
        Convertit la représentation de l'instance en un dictionnaire de valeurs natives.
        """
        representation = super().to_representation(instance)
        representation['type_categorie'] = TypeCategorieSerializer(instance.type_categorie).data
        return representation


class RetrieveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Retrieve
        fields = ['id', 'date_retrieve', 'find', 'info_temoins', 'photo', 'document']


class PublishSerializer(serializers.ModelSerializer):
    class Meta:
        model = Publish
        fields = ['id', 'date_published', 'retrieve', 'is_publish']


class InfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Info
        fields = ['id', 'adresse', 'tel', 'email', 'pourcentage', 'valeur_reel']


class TypeAbonnementSerializer(serializers.ModelSerializer):
    class Meta:
        model = TypeAbonnement
        fields = ['id', 'nom', 'type_notification', 'valeur', 'nombre_de_jours', 'is_active']


class TypeNotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = TypeNotification
        fields = ['id', 'nom']


class TemoignageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Temoignage
        fields = ['id', 'user', 'date_temoignage', 'temoignage']


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'date', 'souscription', 'retrieve', 'publish']


class SouscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Souscription
        fields = ['id', 'date', 'type_abonnement', 'user', 'is_valid', 'is_canceled', 'date_canceled', 'start_date', 'end_date']

    def to_representation(self, instance):
        """
        Convertit la représentation de l'instance en un dictionnaire de valeurs natives.
        """
        representation = super().to_representation(instance)
        representation['type_abonnement'] = TypeAbonnementSerializer(instance.type_abonnement).data
        representation['user'] = UserSerializer(instance.user).data
        return representation


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['id', 'date', 'montant_operation', 'montant_remis', 'relicat']
