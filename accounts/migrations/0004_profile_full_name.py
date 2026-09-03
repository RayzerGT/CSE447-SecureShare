from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_alter_profile_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='full_name',
            field=models.CharField(blank=True, max_length=150),
        ),
    ]
