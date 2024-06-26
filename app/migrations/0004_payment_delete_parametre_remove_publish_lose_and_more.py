# Generated by Django 4.2.11 on 2024-05-08 13:47

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_temoignage_user'),
    ]

    operations = [
        migrations.CreateModel(
            name='Payment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateTimeField(default=django.utils.timezone.now)),
                ('montant_operation', models.DecimalField(blank=True, decimal_places=3, max_digits=10)),
                ('montant_remis', models.DecimalField(blank=True, decimal_places=3, max_digits=10)),
                ('relicat', models.DecimalField(blank=True, decimal_places=3, max_digits=10)),
            ],
        ),
        migrations.DeleteModel(
            name='Parametre',
        ),
        migrations.RemoveField(
            model_name='publish',
            name='lose',
        ),
        migrations.AddField(
            model_name='find',
            name='couleur',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='find',
            name='immatricul',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='find',
            name='marque',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='find',
            name='ram',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='find',
            name='rom',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AddField(
            model_name='info',
            name='pourcentage',
            field=models.DecimalField(blank=True, decimal_places=2, default=0.0, max_digits=5),
        ),
        migrations.AddField(
            model_name='info',
            name='valeur_reel',
            field=models.PositiveIntegerField(blank=True, default=0),
        ),
    ]
