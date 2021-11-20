from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm, PasswordChangeForm
from django.contrib.auth.models import User

from polls.models import Question


# Create your forms here.

class NewUserForm(UserCreationForm):
	email = forms.EmailField(required=True)

	class Meta:
		model = User
		fields = ("username", "email", "password1", "password2")

	def save(self, commit=True):
		user = super(NewUserForm, self).save(commit=False)
		user.email = self.cleaned_data['email']
		if commit:
			user.save()
		return user
class UserPasswordResetForm(PasswordResetForm):
	email = forms.EmailInput
	
class UserPasswordConfirmForm(PasswordChangeForm):
	password1 = forms.PasswordInput
	password2 = forms.PasswordInput