from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import status
from .models import Car, Motorcycle, Key, USBKey, MobilePhone, Animal, Individual
from .serializers import (
    CarSerializer,
    MotorcycleSerializer,
    KeySerializer,
    USBKeySerializer,
    MobilePhoneSerializer,
    AnimalSerializer,
    IndividualSerializer,
)
from .forms import (
    CarForm,
    MotorcycleForm,
    KeyForm,
    USBKeyForm,
    MobilePhoneForm,
    AnimalForm,
    IndividualForm,
)
import requests


class CarViewSet(viewsets.ModelViewSet):
    queryset = Car.objects.all()
    serializer_class = CarSerializer

    def create(self, request, *args, **kwargs):
        form = CarForm(request.data)
        if form.is_valid():
            car_instance = form.save(commit=False)
            car_instance.save()

            # Utilisez le sérialiseur pour renvoyer la réponse
            serializer = self.get_serializer(car_instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        form = CarForm(request.data, instance=instance)
        if form.is_valid():
            form.save()

            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class MotorcycleViewSet(viewsets.ModelViewSet):
    queryset = Motorcycle.objects.all()
    serializer_class = MotorcycleSerializer

    def create(self, request, *args, **kwargs):
        form = MotorcycleForm(request.data)
        if form.is_valid():
            motorcycle_instance = form.save(commit=False)
            motorcycle_instance.save()

            serializer = self.get_serializer(motorcycle_instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        form = MotorcycleForm(request.data, instance=instance)
        if form.is_valid():
            form.save()

            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class KeyViewSet(viewsets.ModelViewSet):
    queryset = Key.objects.all()
    serializer_class = KeySerializer

    def create(self, request, *args, **kwargs):
        form = KeyForm(request.data)
        if form.is_valid():
            key_instance = form.save(commit=False)
            key_instance.save()

            serializer = self.get_serializer(key_instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        form = KeyForm(request.data, instance=instance)
        if form.is_valid():
            form.save()

            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class USBKeyViewSet(viewsets.ModelViewSet):
    queryset = USBKey.objects.all()
    serializer_class = USBKeySerializer

    def create(self, request, *args, **kwargs):
        form = USBKeyForm(request.data)
        if form.is_valid():
            usb_key_instance = form.save(commit=False)
            usb_key_instance.save()

            serializer = self.get_serializer(usb_key_instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        form = USBKeyForm(request.data, instance=instance)
        if form.is_valid():
            form.save()

            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class MobilePhoneViewSet(viewsets.ModelViewSet):
    queryset = MobilePhone.objects.all()
    serializer_class = MobilePhoneSerializer

    def create(self, request, *args, **kwargs):
        form = MobilePhoneForm(request.data)
        if form.is_valid():
            mobile_phone_instance = form.save(commit=False)
            mobile_phone_instance.save()

            serializer = self.get_serializer(mobile_phone_instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        form = MobilePhoneForm(request.data, instance=instance)
        if form.is_valid():
            form.save()

            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class AnimalViewSet(viewsets.ModelViewSet):
    queryset = Animal.objects.all()
    serializer_class = AnimalSerializer

    def create(self, request, *args, **kwargs):
        form = AnimalForm(request.data)
        if form.is_valid():
            animal_instance = form.save(commit=False)
            animal_instance.save()

            serializer = self.get_serializer(animal_instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        form = AnimalForm(request.data, instance=instance)
        if form.is_valid():
            form.save()

            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class IndividualViewSet(viewsets.ModelViewSet):
    queryset = Individual.objects.all()
    serializer_class = IndividualSerializer

    def create(self, request, *args, **kwargs):
        form = IndividualForm(request.data)
        if form.is_valid():
            individual_instance = form.save(commit=False)
            individual_instance.save()

            serializer = self.get_serializer(individual_instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        form = IndividualForm(request.data, instance=instance)
        if form.is_valid():
            form.save()

            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)




def share_location_api():
    # Remplacez YOUR_GOOGLE_MAPS_API_KEY par votre clé d'API Google Maps
    api_key = "YOUR_GOOGLE_MAPS_API_KEY"
    
    # Assurez-vous d'ajuster l'URL en fonction de votre API de géocodage inversé
    url = f"https://maps.googleapis.com/maps/api/geocode/json?latlng=XX.XXXXX,YY.YYYYY&key={api_key}"

    try:
        response = requests.get(url)
        data = response.json()

        if response.status_code == 200 and data['status'] == 'OK':
            # Récupérez la première adresse trouvée dans la réponse
            formatted_address = data['results'][0]['formatted_address']
            return formatted_address
        else:
            # Gérez les erreurs selon vos besoins
            return "Erreur lors de la récupération de la localisation"

    except Exception as e:
        # Gérez les exceptions selon vos besoins
        return "Erreur lors de la récupération de la localisation"
