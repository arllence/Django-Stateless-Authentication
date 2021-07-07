import uuid
from django.db import models
from django.conf import settings
from django.contrib.postgres.fields import JSONField


# Create your models here.
class Entity(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=100)
    code = models.CharField(max_length=100, unique=True)
    date_created = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.id

    class Meta:
        db_table = u'"{}"."entity"'.format(settings.CONFIGURATION_MANAGER_SCHEMA)


class Registry(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=100)
    code = models.CharField(max_length=100, unique=True)
    entity = models.models.ForeignKey(
        Entity,
        related_name="configuration_manager_entity",
        on_delete=models.CASCADE,
    )
    date_created = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.id

    class Meta:
        db_table = u'"{}"."registry"'.format(settings.CONFIGURATION_MANAGER_SCHEMA)