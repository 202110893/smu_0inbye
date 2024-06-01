from django.db import models

# Create your models here.

class Address(models.Model):
    full_address = models.CharField(max_length=255)

    def __str__(self):
        return self.full_address