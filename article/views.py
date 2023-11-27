from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view
import requests
from decouple import config

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




TOMTOM_API_KEY = config('TOMTOM_API_KEY')

def location_view(request, id):
    try:
        result_data = []

        classes_to_check = [
            CarViewSet,
            MotorcycleViewSet,
            KeyViewSet,
            USBKeyViewSet,
            MobilePhoneViewSet,
            AnimalViewSet,
            IndividualViewSet
        ]

        for class_viewset in classes_to_check:
            model_instance = get_object_or_404(class_viewset.queryset, id=id, is_find=True)

            if not model_instance.found_location:
                raise ValueError(f"Found location not provided for {model_instance.__class__.__name__} with id {model_instance.id}")

            base_url = "https://api.tomtom.com/search/2/search/"
            params = {
                'key': TOMTOM_API_KEY,
                'query': model_instance.found_location,
            }

            response = requests.get(base_url, params=params)
            data = response.json()

            if 'results' in data and data['results']:
                # Récupérer les coordonnées du premier résultat
                coordinates = data['results'][0]['position']
                result_entry = {
                    'class_name': model_instance.__class__.__name__,
                    'id': model_instance.id,
                    'coordinates': coordinates,
                }
                result_data.append(result_entry)
            else:
                result_data.append({'class_name': model_instance.__class__.__name__, 'id': model_instance.id, 'coordinates': None})

        return JsonResponse({'data': result_data})

    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

