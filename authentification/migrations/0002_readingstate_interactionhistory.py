# Generated by Django 4.2.7 on 2023-12-06 21:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentification', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ReadingState',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('read_state', models.CharField(max_length=20)),
                ('last_read_date', models.DateField(auto_now=True)),
                ('material', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reading_states', to='authentification.material')),
                ('student', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reading_states', to='authentification.customuser')),
            ],
        ),
        migrations.CreateModel(
            name='InteractionHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('interaction_type', models.CharField(choices=[('upload', 'Upload'), ('read', 'Read')], max_length=20)),
                ('interaction_date', models.DateField(auto_now_add=True)),
                ('material', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='interactions', to='authentification.material')),
                ('student', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='interactions', to='authentification.customuser')),
            ],
        ),
    ]