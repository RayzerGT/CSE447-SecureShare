from django.core.management.base import BaseCommand

from posts.encryption import decrypt_caption, decrypt_image, encrypt_and_store, seal_caption
from posts.imaging import prepare_upload
from posts.models import Post


class Command(BaseCommand):
    help = "Re-encode existing posts so they have an encrypted thumbnail and a caption MAC."

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true", help="Re-encode every post, not just incomplete ones.")

    def handle(self, *args, **options):
        queryset = Post.objects.select_related("owner").all()
        if not options["force"]:
            queryset = queryset.filter(encrypted_thumbnail_blob__isnull=True) | queryset.filter(caption_mac_tag="")
            queryset = queryset.distinct()

        total = queryset.count()
        if not total:
            self.stdout.write(self.style.SUCCESS("Nothing to backfill - every post already has a thumbnail and caption MAC."))
            return

        self.stdout.write(self.style.MIGRATE_HEADING(f"Backfilling {total} post(s)"))
        done = 0
        for post in queryset.iterator():
            try:
                original = decrypt_image(post)
                text = decrypt_caption(post)
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f"  skipped post #{post.pk}: {type(exc).__name__}: {exc}"))
                continue

            full_image, thumbnail = prepare_upload(original)
            encrypt_and_store(post, full_image, text, thumbnail)
            seal_caption(post)
            post.save(
                update_fields=[
                    "caption",
                    "encrypted_image_blob",
                    "encrypted_thumbnail_blob",
                    "encrypted_caption",
                    "mac_tag",
                    "caption_mac_tag",
                ]
            )
            done += 1
            self.stdout.write(f"  post #{post.pk}: {len(original):,} B -> {len(full_image):,} B full, {len(thumbnail):,} B thumb")

        self.stdout.write(self.style.SUCCESS(f"\nBackfilled {done}/{total} post(s)."))
