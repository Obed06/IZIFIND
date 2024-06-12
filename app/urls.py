from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from .views import *




urlpatterns = [
	path('users/', UserViewSet.as_view({'get': 'list', 'post': 'create'}), name='user-list-create'),
	path('users/<int:pk>/', UserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='user-detail-update-delete'),
	path('register/', RegisterUserView.as_view(), name='register'),
	path('api/delete-user/<int:user_id>/', delete_user, name='delete_user'),

	path('login/', login_view, name='login'),
	path('reset_password_email/', reset_password_email, name='reset_password_email'),
	path('reset_password_confirm/<str:uidb64>/<str:token>', reset_password_confirm, name='reset_password_confirm'),
	path('logout/', logout_view, name='logout'),

	path('send-notification/', SendNotificationViewSet.as_view({'post': 'create'}), name='send-notification'),
	path('send_email/', xend_email, name='send_email'),

	path('loses/', LoseViewSet.as_view({'get': 'list', 'post': 'create'}), name='lose-list-create'),
	path('loses/<int:pk>/', LoseViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='lose-detail-update-delete'),

	path('find/', FindViewSet.as_view({'get': 'list', 'post': 'create'}), name='find-list-create'),
	path('find/<int:pk>/', FindViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='find-detail-update-delete'),

	path('type-categorie/', TypeCategorieViewSet.as_view({'get': 'list', 'post': 'create'}), name='type-categorie-list-create'),
	path('type-categorie/<int:pk>/', TypeCategorieViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='type-categorie-detail-update-delete'),

	path('categorie/', CategorieViewSet.as_view({'get': 'list', 'post': 'create'}), name='categorie-list-create'),
	path('categorie/<int:pk>/', CategorieViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='categorie-detail-update-delete'),

	path('retrieve/', RetrieveViewSet.as_view({'get': 'list', 'post': 'create'}), name='retrieve-list-create'),
	path('retrieve/<int:pk>/', RetrieveViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='retrieve-detail-update-delete'),

	path('publish/', PublishViewSet.as_view({'get': 'list', 'post': 'create'}), name='publish-list-create'),
	path('publish/<int:pk>/', PublishViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='publish-detail-update-delete'),

	path('info/', InfoViewSet.as_view({'get': 'list', 'post': 'create'}), name='info-list-create'),
	path('info/<int:pk>/', InfoViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='info-detail-update-delete'),

	path('type-notification/', TypeNotificationViewSet.as_view({'get': 'list', 'post': 'create'}), name='type-notification-list-create'),
	path('type-notification/<int:pk>/', TypeNotificationViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='type-notification-detail-update-delete'),

	path('type-abonnement/', TypeAbonnementViewSet.as_view({'get': 'list', 'post': 'create'}), name='type-abonnement-list-create'),
	path('type-abonnement/<int:pk>/', TypeAbonnementViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='type-abonnement-detail-update-delete'),

	path('temoignage/', TemoignageViewSet.as_view({'get': 'list', 'post': 'create'}), name='temoignage-list-create'),
	path('temoignage/<int:pk>/', TemoignageViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='temoignage-detail-update-delete'),

	path('souscription/', SouscriptionViewSet.as_view({'get': 'list', 'post': 'create'}), name='souscription-list-create'),
	path('souscription/<int:pk>/', SouscriptionViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='souscription-detail-update-delete'),

	path('notification/', NotificationViewSet.as_view({'get': 'list', 'post': 'create'}), name='notification-list-create'),
	path('notification/<int:pk>/', NotificationViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='notification-detail-update-delete'),

	path('payment/', PaymentViewSet.as_view({'get': 'list', 'post': 'create'}), name='payment-list-create'),
	path('payment/<int:pk>/', PaymentViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='payment-detail-update-delete'),



###################    LES PAGES    ###################


	path('page_register/', page_register, name='page_register'),
	path('page_login/', page_login, name='page_login'),
	path('page_password_email/', page_password_email, name='page_password_email'),
	path('home/', home, name='home'),
	
	path('perdu/', lose, name='perdu'),
	path('trouve/', find, name='trouve'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
