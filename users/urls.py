from django.urls import path
from .views import *

urlpatterns = [
	path('users/', UserViewSet.as_view({'get': 'list', 'post': 'create'}), name='user-list'),

    path('users/<int:pk>/', UserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='user-detail'),
    path('api/delete-user/<int:user_id>/', delete_user, name='delete_user'),

    path('users/<int:pk>/send-sms/', UserViewSet.as_view({'post': 'send_sms'}), name='user-send-sms'),
	path('register/', RegisterUserView.as_view(), name='register'),

	path('login/', login_view, name='login'),
	path('reset_password_email/', reset_password_email, name='reset_password_email'),
	path('reset_password_confirm/<uidb64>/<token>', reset_password_confirm, name='reset_password_confirm'),

	path('api/messages/', MessageViewSet.as_view({'get': 'list', 'post': 'create'}), name='message-list'),
    path('api/messages/<int:pk>/', MessageViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='message-detail'),
    path('api/messages/inbox/', MessageViewSet.as_view({'get': 'inbox'}), name='message-inbox'),
    path('api/messages/<int:pk>/send_message/', MessageViewSet.as_view({'post': 'send_message'}), name='message-send'),
]
