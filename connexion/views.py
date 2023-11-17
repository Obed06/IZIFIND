from django.shortcuts import render



def index(request):
	return render(request, 'main.html')

def login(request):
	return render(request, 'login.html')

def register(request):
	return render(request, 'register.html')

def reset_password(request):
	return render(request, 'password_reset.html')