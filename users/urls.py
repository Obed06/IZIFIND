from django.urls import path
from .views import *

urlpatterns = [
	path('users/', UserViewSet.as_view({'get': 'list', 'post': 'create'}), name='user-list'),
	path('register/', RegisterUserView.as_view(), name='register'),
	
    path('users/<int:pk>/', UserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='user-detail'),
    path('api/delete-user/<int:user_id>/', delete_user, name='delete_user'),

	path('login/', login_view, name='login'),
	path('reset_password_email/', reset_password_email, name='reset_password_email'),
	path('reset_password_confirm/<uidb64>/<token>', reset_password_confirm, name='reset_password_confirm'),

	path('messages/', MessageViewSet.as_view({'get': 'list', 'post': 'create'}), name='message-list'),
    path('messages/<int:pk>/', MessageViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='message-detail'),
    path('messages/<int:pk>/send_message/', MessageViewSet.as_view({'post': 'send_message'}), name='message-send'),
    path('messages/<int:pk>/mark_as_read/', MessageViewSet.as_view({'post': 'mark_as_read'}), name='msg-mark-as-read'),

    path('send-notification/', SendNotificationViewSet.as_view({'post': 'create'}), name='send-notification'),

    ############    LES PAGES    ############
    path('page_register/', page_register, name='page_register'),
    path('page_login/', page_login, name='page_login'),
    path('page_password_email/', page_password_email, name='page_password_email'),
    path('home/', home, name='home'),
]
