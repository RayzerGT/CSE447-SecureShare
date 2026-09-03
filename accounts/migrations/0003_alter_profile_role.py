from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_activesession_expires_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='role',
            field=models.CharField(choices=[('user', 'Standard User'), ('admin', 'Admin'), ('developer', 'Developer')], default='user', max_length=16),
        ),
    ]
