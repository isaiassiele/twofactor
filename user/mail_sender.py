from django.core.mail import send_mail



def send_otp(email,message):
      # Send the OTP code to the user's email address
    send_mail(
        'Your OTP code',
        f'Your OTP code is {message}',
        'from@example.com',
        [email],
        fail_silently=False,
    )