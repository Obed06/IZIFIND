from django.urls import path
from .views import *



urlpatterns = [
    path('cars/', CarViewSet.as_view({'get': 'list', 'post': 'create'}), name='car-list'),
    path('cars/<int:pk>/', CarViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='car-detail'),
    path('cars/alphabetical-sort/', CarViewSet.as_view({'get': 'alphabetical_sort'}), name='car-alphabetical-sort'),
    path('cars/search/', CarViewSet.as_view({'get': 'search'}), name='car-search'),

    path('motorcycles/', MotorcycleViewSet.as_view({'get': 'list', 'post': 'create'}), name='motorcycle-list'),
    path('motorcycles/<int:pk>/', MotorcycleViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='motorcycle-detail'),
    path('motorcycles/alphabetical-sort/', MotorcycleViewSet.as_view({'get': 'alphabetical_sort'}), name='motorcycle-alphabetical-sort'),
    path('motorcycles/search/', MotorcycleViewSet.as_view({'get': 'search'}), name='motorcycle-search'),

    path('keys/', KeyViewSet.as_view({'get': 'list', 'post': 'create'}), name='key-list'),
    path('keys/<int:pk>/', KeyViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='key-detail'),
    path('keys/alphabetical-sort/', KeyViewSet.as_view({'get': 'alphabetical_sort'}), name='key-alphabetical-sort'),
    path('keys/search/', KeyViewSet.as_view({'get': 'search'}), name='key-search'),

    path('usbkeys/', USBKeyViewSet.as_view({'get': 'list', 'post': 'create'}), name='usbkey-list'),
    path('usbkeys/<int:pk>/', USBKeyViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='usbkey-detail'),
    path('usbkeys/alphabetical-sort/', USBKeyViewSet.as_view({'get': 'alphabetical_sort'}), name='usbkey-alphabetical-sort'),
    path('usbkeys/search/', USBKeyViewSet.as_view({'get': 'search'}), name='usbkey-search'),

    path('mobilephones/', MobilePhoneViewSet.as_view({'get': 'list', 'post': 'create'}), name='mobilephone-list'),
    path('mobilephones/<int:pk>/', MobilePhoneViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='mobilephone-detail'),
    path('mobilephones/alphabetical-sort/', MobilePhoneViewSet.as_view({'get': 'alphabetical_sort'}), name='mobilephone-alphabetical-sort'),
    path('mobilephones/search/', MobilePhoneViewSet.as_view({'get': 'search'}), name='mobilephone-search'),

    path('animals/', AnimalViewSet.as_view({'get': 'list', 'post': 'create'}), name='animal-list'),
    path('animals/<int:pk>/', AnimalViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='animal-detail'),
    path('animals/alphabetical-sort/', AnimalViewSet.as_view({'get': 'alphabetical_sort'}), name='animal-alphabetical-sort'),
    path('animals/search/', AnimalViewSet.as_view({'get': 'search'}), name='animal-search'),

    path('individuals/', IndividualViewSet.as_view({'get': 'list', 'post': 'create'}), name='individual-list'),
    path('individuals/<int:pk>/', IndividualViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='individual-detail'),
    path('individuals/alphabetical-sort/', IndividualViewSet.as_view({'get': 'alphabetical_sort'}), name='individual-alphabetical-sort'),
    path('individuals/search/', IndividualViewSet.as_view({'get': 'search'}), name='individual-search'),

    path('location/<int:id>/', location_view, name='location-view'),

    path('items/', ItemViewSet.as_view({'get': 'list', 'post': 'create'}), name='item-list'),
    path('items/<int:pk>/', ItemViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='item-detail'),
    path('items/alphabetical-sort/', ItemViewSet.as_view({'get': 'alphabetical_sort'}), name='item-alphabetical-sort'),
    path('items/search/', ItemViewSet.as_view({'get': 'search'}), name='item-search'),
   
]
