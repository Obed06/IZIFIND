from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from .views import *


urlpatterns = [
	path('users/', UserViewSet.as_view({'get': 'list', 'post': 'create'}), name='user-list'),
	path('register/', RegisterUserView.as_view(), name='register'),
	
    path('users/<int:pk>/', UserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='user-detail'),
    path('api/delete-user/<int:user_id>/', delete_user, name='delete_user'),

	path('login/', login_view, name='login'),
	path('reset_password_email/', reset_password_email, name='reset_password_email'),
	path('reset_password_confirm/<str:uidb64>/<str:token>', reset_password_confirm, name='reset_password_confirm'),

    path('send-notification/', SendNotificationViewSet.as_view({'post': 'create'}), name='send-notification'),

    path('send_email/', xend_email, name='send_email'),

    path('loses/', LoseViewSet.as_view({'get': 'list', 'post': 'create'}), name='lose-list'),
    path('loses/<int:pk>/', LoseViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='lose-detail'),

    path('find/', FindViewSet.as_view({'get': 'list', 'post': 'create'}), name='find-list'),
    path('find/<int:pk>/', FindViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='find-detail'),


###################    LES PAGES    ###################


    path('page_register/', page_register, name='page_register'),
    path('page_login/', page_login, name='page_login'),
    path('page_password_email/', page_password_email, name='page_password_email'),
    path('home/', home, name='home'),
    
    path('perdu/', lose, name='perdu'),
    path('trouve/', find, name='trouve'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
