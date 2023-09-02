from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.validators import ASCIIUsernameValidator, UnicodeUsernameValidator
from django.core.validators import MinLengthValidator
from django.contrib.auth.password_validation import validate_password





def check_email(value):
    if User.objects.filter(email=value).exists():
        return forms.ValidationError("Account with this Email Address already exists")

class UserRegistrationForm(forms.Form):
    username = forms.CharField(
        label='Username',
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        validators=[ASCIIUsernameValidator()],
    )

    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={'class': 'form-control'}),
        validators=[check_email],
    )

    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        validators=[
            MinLengthValidator(8, message="Password must be at least 8 characters."),
            validate_password,  # Enforce Django's default password validation
        ]
    )

    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        validators=[
            MinLengthValidator(8, message="Password must be at least 8 characters."),
        ]
    )

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            self.add_error('password2', "Passwords do not match.")
        
        # Check if the provided username or email already exist
        username = cleaned_data.get("username")
        email = cleaned_data.get("email")
        if User.objects.filter(username=username).exists():
            self.add_error('username', "Username already exists.")
        if User.objects.filter(email=email).exists():
            self.add_error('email', "Email already exists.")

        return cleaned_data
