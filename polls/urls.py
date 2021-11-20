from django.urls import path

from . import views

app_name = 'polls'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('<int:pk>/', views.DetailView.as_view(), name='detail'),
    path('<int:pk>/results/', views.ResultsView.as_view(), name='results'),
    path('<int:question_id>/vote/', views.vote, name='vote'),

    path('register', views.register_request, name='register'),
    path('login', views.login_request, name='login'),
    path("logout", views.logout_request, name="logout"),
    #path("password_reset", views.password_reset_request, name="password_reset"),
    #path("password_confirm/<uidb64>/<token>/", views.password_confirm_request, name="password_confirm"),

    path("editor", views.editor, name="editor"),
    path("create", views.create, name='create')
]
