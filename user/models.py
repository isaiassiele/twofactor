from django.db import models
from django.contrib.auth.models import User

class DeviceInformation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    latitude =models.CharField(max_length=200)
    longitude =models.CharField(max_length=200)

    ip_address = models.CharField(max_length=200)
    location_name = models.CharField(max_length=255)  # Store location name

    def __str__(self):
        return f"Device Info for {self.user.username}"