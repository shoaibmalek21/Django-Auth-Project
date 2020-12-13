from django.urls import path, include
from . import views
from django.contrib.auth.decorators import login_required


urlpatterns = [
	path('register', views.RegisterView.as_view(),name='register'),
	path('login', views.LoginView.as_view(),name='login'),
	path('logout', views.LogoutView.as_view(),name='logout'),
	path('', login_required(views.HomeView.as_view()),name='home'),
	path('activate/<uidb64>/<token>', views.ActivateACView.as_view(),name='activate'),
]