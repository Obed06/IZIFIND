from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import *



class UserAdmin(BaseUserAdmin):
    list_display = ('id', 'email_or_phone', 'last_login_date' ,'last_modify_date', 'deactivate_date', 'first_name', 'last_name', 'is_staff', 'is_admin', 'is_active')
    list_filter = ('is_admin', 'is_active')
    list_editable = ('first_name', 'last_name')

    fieldsets = (
        (None, {'fields': ('email_or_phone', 'password', 'first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_admin', 'is_staff', 'is_active')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email_or_phone', 'password1', 'password2')
        }),
    )

    search_fields = ('email_or_phone',)
    ordering = ('email_or_phone',)
    filter_horizontal = ()



admin.site.register(User, UserAdmin)
admin.site.register(TypeCategorie)
admin.site.register(Categorie)
admin.site.register(TypeNotification)
admin.site.register(TypeAbonnement)
admin.site.register(Souscription)

admin.site.register(Publish)
admin.site.register(Temoignage)
admin.site.register(Lose)
admin.site.register(Find)
admin.site.register(Retrieve)
admin.site.register(Info)
admin.site.register(Payment)
