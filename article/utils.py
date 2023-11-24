from django.core.cache import cache
from .views import share_location_api


def update_changed_elements(instance: Model):
    changed_elements = cache.get('changed_elements', {})
    
    model_name = instance.__class__.__name__
    instance_id = instance.id

    if model_name not in changed_elements:
        changed_elements[model_name] = []

    if instance_id not in changed_elements[model_name]:
        changed_elements[model_name].append(instance_id)
        cache.set('changed_elements', changed_elements)


def add_share_location(instance):
    instance.share_location = share_location_api()
    instance.save()
