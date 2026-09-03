import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Post',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(upload_to='posts/')),
                ('caption', models.TextField(blank=True)),
                ('encrypted_caption', models.TextField(blank=True)),
                ('encrypted_image_blob', models.BinaryField(blank=True, null=True)),
                ('mac_tag', models.CharField(blank=True, max_length=255)),
                ('visibility', models.CharField(choices=[('public', 'Public'), ('private', 'Private'), ('role_restricted', 'Role-Restricted')], default='public', max_length=20)),
                ('allowed_role', models.CharField(blank=True, help_text='Role required when role-restricted.', max_length=16)),
                ('is_flagged', models.BooleanField(default=False)),
                ('is_deleted', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='posts', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
