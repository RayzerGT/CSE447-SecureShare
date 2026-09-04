from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from accounts.models import Profile
from accounts.views import _avatar_context
from crypto_core import media_vault
from messaging.models import Message
from messaging.views import _image_context
from posts.imaging import prepare_attachment, prepare_avatar


class Command(BaseCommand):
    help = "Encrypt any plaintext image still sitting in MEDIA_ROOT, then delete the plaintext file."

    def add_arguments(self, parser):
        parser.add_argument("--keep-files", action="store_true", help="Encrypt but do not delete the plaintext files.")

    def handle(self, *args, **options):
        root = Path(settings.MEDIA_ROOT)
        if not root.exists():
            self.stdout.write(self.style.SUCCESS("No media directory - nothing to secure."))
            return

        self.stdout.write(self.style.MIGRATE_HEADING("Encrypting profile photos"))
        for profile in Profile.objects.select_related("user").exclude(avatar="").exclude(avatar=None):
            if profile.encrypted_avatar_blob:
                self.stdout.write(f"  already encrypted  {profile.user.username}")
                continue
            path = root / profile.avatar.name
            if not path.exists():
                self.stdout.write(self.style.WARNING(f"  missing file       {profile.avatar.name}"))
                continue
            blob, tag = media_vault.seal(
                profile.user, _avatar_context(profile), prepare_avatar(path.read_bytes())
            )
            profile.encrypted_avatar_blob = blob
            profile.avatar_mac_tag = tag
            profile.save(update_fields=["encrypted_avatar_blob", "avatar_mac_tag"])
            self.stdout.write(f"  encrypted          {profile.user.username} ({path.stat().st_size:,} B)")

        self.stdout.write(self.style.MIGRATE_HEADING("\nEncrypting message photos"))
        for message in Message.objects.select_related("sender", "recipient").exclude(image="").exclude(image=None):
            if message.encrypted_image_blob:
                self.stdout.write(f"  already encrypted  message #{message.pk}")
                continue
            path = root / message.image.name
            if not path.exists():
                self.stdout.write(self.style.WARNING(f"  missing file       {message.image.name}"))
                continue
            blob, tag = media_vault.seal(
                message.recipient, _image_context(message), prepare_attachment(path.read_bytes())
            )
            message.encrypted_image_blob = blob
            message.image_mac_tag = tag
            message.save(update_fields=["encrypted_image_blob", "image_mac_tag"])
            self.stdout.write(f"  encrypted          message #{message.pk} ({path.stat().st_size:,} B)")

        if options["keep_files"]:
            self.stdout.write(self.style.WARNING("\n--keep-files given: plaintext files left on disk."))
            return

        self.stdout.write(self.style.MIGRATE_HEADING("\nDeleting plaintext files"))
        removed = freed = 0
        for path in sorted(root.rglob("*")):
            if path.is_file():
                freed += path.stat().st_size
                path.unlink()
                removed += 1
                self.stdout.write(f"  deleted  {path.relative_to(root)}")
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir() and not any(path.iterdir()):
                path.rmdir()

        self.stdout.write(
            self.style.SUCCESS(f"\nRemoved {removed} plaintext file(s), {freed:,} bytes. MEDIA_ROOT now holds no images.")
        )
