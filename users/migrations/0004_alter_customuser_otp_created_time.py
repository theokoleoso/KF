# Generated by Django 5.0.3 on 2024-04-08 11:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_customuser_otp_created_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='otp_created_time',
            field=models.DateTimeField(),
        ),
    ]