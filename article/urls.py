from django.urls import path
from .views import *



urlpatterns = [
    path('cars/', CarViewSet.as_view({'get': 'list', 'post': 'create'}), name='car-list'),
    path('cars/<int:pk>/', CarViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='car-detail'),

    path('motorcycles/', MotorcycleViewSet.as_view({'get': 'list', 'post': 'create'}), name='motorcycle-list'),
    path('motorcycles/<int:pk>/', MotorcycleViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='motorcycle-detail'),

    path('keys/', KeyViewSet.as_view({'get': 'list', 'post': 'create'}), name='key-list'),
    path('keys/<int:pk>/', KeyViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='key-detail'),

    path('usbkeys/', USBKeyViewSet.as_view({'get': 'list', 'post': 'create'}), name='usbkey-list'),
    path('usbkeys/<int:pk>/', USBKeyViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='usbkey-detail'),

    path('mobilephones/', MobilePhoneViewSet.as_view({'get': 'list', 'post': 'create'}), name='mobilephone-list'),
    path('mobilephones/<int:pk>/', MobilePhoneViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='mobilephone-detail'),

    path('animals/', AnimalViewSet.as_view({'get': 'list', 'post': 'create'}), name='animal-list'),
    path('animals/<int:pk>/', AnimalViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='animal-detail'),

    path('individuals/', IndividualViewSet.as_view({'get': 'list', 'post': 'create'}), name='individual-list'),
    path('individuals/<int:pk>/', IndividualViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='individual-detail'),

    path('location/<int:id>/', location_view, name='location-view'),

    path('items/', ItemViewSet.as_view({'get': 'list', 'post': 'create'}), name='item-list'),
    path('items/<int:pk>/', ItemViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='item-detail'),
   
]
