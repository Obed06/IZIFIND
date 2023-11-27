from django.urls import path
from .views import *

urlpatterns = [
	path('api/user/<int:pk>/', UserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update'}), name='user-detail'),
	path('register/', RegisterUserView.as_view(), name='register'),
	path('api/delete-user/<int:user_id>/', delete_user, name='delete_user'),

	path('login/', login_view, name='login'),
	path('reset_password_email/', reset_password_email, name='reset_password_email'),
	path('reset_password_confirm/<uidb64>/<token>', reset_password_confirm, name='reset_password_confirm'),
]
