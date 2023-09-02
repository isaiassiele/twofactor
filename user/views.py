from sqlite3 import IntegrityError
from django.shortcuts import redirect, render
from django.core.exceptions import SuspiciousOperation

from geopy.distance import geodesic  # Import the geodesic function for distance calculation

from .models import DeviceInformation
import geocoder
from ipinfo import getHandler


from django.views.decorators.csrf import csrf_exempt



from cryptography.fernet import Fernet



# Create your views here.
from decimal import Decimal


from .forms import UserRegistrationForm
import random
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_protect
import bcrypt

from django.contrib import messages
from django.http import HttpResponse

from django.contrib.auth import authenticate,login
from django.contrib.auth.decorators import login_required
import base64  # Import the base64 module

#importing email function that's send email
from .mail_sender import send_otp
import string
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



# Generate the encryption key using PBKDF2HMAC
def generate_fernet_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# Use the key to initialize Fernet
def initialize_fernet(key):
    return Fernet(key)

salt = os.urandom(16)  # Generate a random 16-byte salt
secret_key = os.urandom(32)  # Generate a random 32-byte secret key

key = generate_fernet_key(secret_key, salt)
fernet = initialize_fernet(key)

def generate_otp(length=6):
    characters = string.digits + string.ascii_letters
    otp = ''.join(random.choice(characters) for _ in range(length))
    encrypted_otp = fernet.encrypt(otp.encode('utf-8'))
    return encrypted_otp.decode('utf-8')


# Generate the encryption key
encryption_key = Fernet.generate_key()
fernet = Fernet(encryption_key)


country_encryption_key = Fernet.generate_key()
country_fernet = Fernet(country_encryption_key)


@login_required
def dashboard_view(request):
    user = request.user

    try:
        device_info = DeviceInformation.objects.get(user=user)
    except DeviceInformation.DoesNotExist:
        device_info = None



    context = {'user': user, 'decrypted_email': 'decrypted_email', 'decrypted_location':' decrypted_location', 'device_info': device_info}

    return render(request, 'dashboard.html', context)








def register_view(request):
    if request.method == 'POST':
        userRegForm = UserRegistrationForm(request.POST)
        

        if userRegForm.is_valid():
            email = userRegForm.cleaned_data['email']
          
            encrypted_email = fernet.encrypt(email.encode('utf-8')).decode('utf-8')
    
            username = userRegForm.cleaned_data['username']
            password1 = userRegForm.cleaned_data['password1']
            hashed_password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())

            request.session['email'] = encrypted_email
            request.session['username'] = username
            request.session['password'] = password1

            encrypted_otp = generate_otp()
            request.session['encrypted_otp'] = encrypted_otp

            message = f'{fernet.decrypt(encrypted_otp.encode("utf-8")).decode("utf-8")}'
            
            # print(message)
            try:
                send_otp(email, message)
            except Exception as e:
                print("SMTP Error:", str(e))
                error_message = 'An error occurred while sending the OTP. SMTP Error Please try again later'
                messages.error(request, error_message)
                return render(request, 'login.html', {'error_message': error_message})
            return redirect('verify_registration_otp')
    else:
        userRegForm = UserRegistrationForm()

    context = {'userRegForm': userRegForm}
    return render(request, 'register.html', context)

@csrf_exempt
def verify_registration_otp_view(request):
    if request.method == 'POST':
        otp = request.POST['otp']
        saved_encrypted_otp = request.session.get('encrypted_otp')

        # Decrypt the encrypted OTP and compare it with the entered OTP
        decrypted_otp = fernet.decrypt(saved_encrypted_otp.encode('utf-8')).decode('utf-8')

        if otp == decrypted_otp:
            # OTP validation successful, proceed with user registration
            username = request.session.get('username')
            encrypted_email = request.session.get('email')
            email_address = fernet.decrypt(encrypted_email.encode('utf-8')).decode('utf-8')
            password = request.session.get('password')

            try:
                user = User.objects.create_user(username=username, email=encrypted_email, password=password)
                # Get device's latitude and longitude using geocoder
                g = geocoder.ip('me')  # 'me' represents the current device's IP address
                latitude = g.latlng[0]
                longitude = g.latlng[1]
                ip_address = g.ip
                location_name = g.city  # Get the city or location name
                handler = getHandler()
                details = handler.getDetails(ip_address)
                country = details.country_name

                # Encrypt the country information
                encrypted_country = country_fernet.encrypt(country.encode('utf-8')).decode('utf-8')
                encrypted_latitude = fernet.encrypt(str(latitude).encode('utf-8')).decode('utf-8')
                encrypted_longitude = fernet.encrypt(str(longitude).encode('utf-8')).decode('utf-8')
                encrypted_ip_address = fernet.encrypt(ip_address.encode('utf-8')).decode('utf-8')


                                
                      # Save device information in the database
                device_info = DeviceInformation(
                user=user,
                latitude=encrypted_latitude,
                longitude=encrypted_longitude,
                ip_address=encrypted_ip_address,
                location_name=encrypted_country
            )
                device_info.save()
            except IntegrityError:
                messages.error(request, 'Username or email already exists.')
                return redirect('verify_registration_otp')

            request.session.delete('encrypted_otp')
            request.session.delete('username')
            request.session.delete('email')
            request.session.delete('password')

            messages.success(request, 'Registration Successfully Done !!')
            return redirect('/login/')
        else:
            messages.error(request, 'Invalid OTP')

    return render(request, 'verify_registration_otp.html')


def login_view(request):
    try:
        if request.session.get('failed') > 2:
            return HttpResponse('<h1> You have to wait for 5 minutes to login again</h1>')
    except:
        request.session['failed'] = 0
        request.session.set_expiry(100)

    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            request.session['username'] = username
            request.session['password'] = password

            # Generate a plain OTP with a length of 6 characters
            encrypted_otp = generate_otp()
            request.session['login_otp'] = encrypted_otp

            message = f'{fernet.decrypt(encrypted_otp.encode("utf-8")).decode("utf-8")}'
            # print(message)
            try:
                send_otp(email, message)
            except Exception as e:
                print("SMTP Error:", str(e))
                error_message = 'An error occurred while sending the OTP. SMTP Error Please try again later.'
                messages.error(request, error_message)
                return render(request, 'login.html', {'error_message': error_message})



          
            # Get device's latitude, longitude, IP address, and country using ipinfo
            g = geocoder.ip('me')  # 'me' represents the current device's IP address
            latitude = g.latlng[0]
            longitude = g.latlng[1]
            ip_address = g.ip

            handler = getHandler()
            details = handler.getDetails(ip_address)
            country = details.country_name

            # Compare device information with stored information
            try:
                device_info = DeviceInformation.objects.get(user=user)
                # print("Stored Latitude:", device_info.latitude)
                # print("Stored Longitude:", device_info.longitude)
                # print("Stored IP Address:", device_info.ip_address)
                # print("Stored Country:", device_info.location_name)
                # print("Current Latitude:", latitude)
                # print("Current Longitude:", longitude)
                # print("Current IP Address:", ip_address)
                # print("Current Country:", country)

                # Decrypt the stored encrypted country
                stored_encrypted_country = device_info.location_name
                # decrypted_country = country_fernet.decrypt(stored_encrypted_country.encode('utf-8')).decode('utf-8')
                
                # Define a tolerance value for latitude and longitude comparisons
                tolerance = Decimal('0.0001')  # Use Decimal instead of float
                
                if (
                    abs(Decimal(fernet.decrypt(device_info.latitude.encode('utf-8')).decode('utf-8')) - Decimal(latitude)) <= tolerance
                    and abs(Decimal(fernet.decrypt(device_info.longitude.encode('utf-8')).decode('utf-8')) - Decimal(longitude)) <= tolerance
                    and stored_encrypted_country == stored_encrypted_country
                ):
                    return redirect('second_factor')
                else:
                    messages.error(request, 'Device information mismatch. Login denied.')
            except DeviceInformation.DoesNotExist:
                messages.error(request, 'Device information not found. Please contact support.')

        else:
            messages.error(request, 'Username or password is wrong')
    return render(request, 'login.html')


@csrf_exempt
def second_factor_view(request):
    if request.method == "POST":
        username = request.session.get('username')
        password = request.session.get('password')
        encrypted_otp = request.session.get('login_otp')
        u_otp = request.POST['otp']

        if encrypted_otp is None:
            messages.error(request, 'OTP session data not found. Please log in again.')
            return redirect('login')  # Redirect to login page with error message

        decrypted_otp = fernet.decrypt(encrypted_otp.encode('utf-8')).decode('utf-8')

        if u_otp == decrypted_otp:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                request.session.delete('login_otp')


                # Redirect the user to the dashboard after successful authentication
                return redirect('dashboard')
            else:
                messages.error(request, 'Authentication failed')
        else:
            messages.error(request, 'Wrong OTP')

        # Clear the login_otp session data, whether authentication succeeds or fails
        request.session.delete('login_otp')

    return render(request, 'second_factor.html')



def logout_view(request):
    request.session.clear()
   
    return redirect('login')  # Redirect to the login page after logout