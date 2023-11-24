from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.cache import cache
from .utils import update_changed_elements, add_share_location


@receiver(post_save)
def handle_field_change(sender, instance, **kwargs):
    # Vérifiez si le modèle a le champ spécifié 'is_find'
    if hasattr(instance, 'is_find') and isinstance(instance.is_find, bool):
        # Ajoutez l'objet à la liste des éléments modifiés
        update_changed_elements(instance)

        # Si le champ 'is_find' passe à True et 'share_location' n'est pas défini, ajoutez-le
        if instance.is_find and not instance.share_location:
            add_share_location(instance)