from django.shortcuts import get_object_or_404, render, redirect
from django.core.mail import send_mail, BadHeaderError
from django.template import loader
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.views import generic
from django.utils import timezone
import datetime

from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm

from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes

from .models import Question, Choice
from .forms import NewUserForm, UserPasswordResetForm, UserPasswordConfirmForm

# Create your views here.
class IndexView(generic.ListView):
    template_name = 'polls/index.html'
    context_object_name = 'latest_question_list'
    def get_queryset(self):
        return Question.objects.order_by('-pub_date')[:20]

class DetailView(generic.DetailView):
    model = Question
    template_name = 'polls/detail.html'


class ResultsView(generic.DetailView):
    model = Question
    template_name = 'polls/results.html'


def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    try:
        selected_choice = question.choice_set.get(pk=request.POST['choice'])
    except (KeyError, Choice.DoesNotExist):
        return render(request, 'polls/detail.html', {
            'question': question,
            'error_message': "You didn't select a choice.",
        })
    else:
        selected_choice.votes += 1
        selected_choice.save()
        return HttpResponseRedirect(reverse('polls:results', args=(question.id,)))

def editor(request):
    return render(request=request, template_name="polls/editor.html")

def create(request):
    if request.method == "POST":
        question = Question.objects.create(
            question_text = request.POST["question_text"],
            pub_date = datetime.datetime.now(tz=timezone.utc)
        )
        for x in range(2, len(request.POST)):
            choice = Choice.objects.create(
                question = question,
                choice_text = list(request.POST.values())[x],
                votes = 0
            )
        return redirect ("polls:editor" )
    return redirect ("polls:editor")

def register_request(request):
    registerError = False
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Registration successful." )
            return redirect("polls:index")
        registerError = True
    form = NewUserForm()
    return render (request=request, template_name="polls/register.html", context={"register_form":form, "registerError": registerError})

def login_request(request):
    loginError = False
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("polls:index")
            else:
                loginError = True
        else:
                loginError = True
    form = AuthenticationForm()
    return render (request=request, template_name="polls/login.html", context={"login_form":form, "loginError": loginError})

def logout_request(request):
    logout(request)
    return redirect ("polls:index")

'''
def password_reset_request(request):
    processError = False
    if request.method == "POST":
        form = UserPasswordResetForm(request)                                                       
        if form.is_valid():
            email = form.cleaned_data["email"]
            associatedUsers = User.objects.filter(Q(email=email))
            if associatedUsers.exists():
                for user in associatedUsers:
                    subject = "Password Reset Requested"
                    email_template_name = "polls/password_reset_email.html"
                    c = {
                        "email":user.email,
                        'domain':'127.0.0.1:8000',
                        'site_name': 'Website',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, "jann.totterman@gmail.com" , [user.email], fail_silently=False, auth_password="kek")
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                    return render (request=request, template_name="polls/password_reset.html", context={"reset_form":form, "error": processError, "success": True})
            else:
                processError=True
        else:
            processError=True

    form = UserPasswordResetForm(request)
    return render (request=request, template_name="polls/password_reset.html", context={"reset_form":form, "error": processError, "success": False})


def password_confirm_request(request):
    processError = False
    form = UserPasswordConfirmForm(request)
    return render (request=request, template_name="polls/password_confirm.html", context={"confirm_form":form, "error": processError, "success": False})
    
'''