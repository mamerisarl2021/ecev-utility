from django.db import models
from statistics import mode

# Create your models here.
class Todo(models.Model):
    title = models.CharField(max_length=70, blank=False, default='')
    description = models.CharField(max_length=200,blank=False, default='')
    completed = models.BooleanField(default=False)

class Document(models.Model):
    document = models.FileField(upload_to='uploads/%Y/%m/%d')