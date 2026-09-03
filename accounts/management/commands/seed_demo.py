import io

from django.conf import settings
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand, CommandError

from accounts.models import Profile, Role, TwoFactorSettings
from crypto_core.encryption_service import EncryptionService
from messaging.models import Message
from moderation.models import Report
from posts.encryption import encrypt_and_store
from posts.models import Post
from social.models import Comment, FriendRequest, Friendship, Like

TEAM = [
    ("Razeen", "1234", Role.DEVELOPER, "Razeen Hassan"),
    ("Afnan", "1234", Role.DEVELOPER, "Afnan Satter"),
    ("Munia", "1234", Role.DEVELOPER, "Mos. Mahabuba Akter Munia"),
    ("razeen_admin", "123", Role.ADMIN, "Razeen (admin account)"),
]

SAMPLE_USERS = [
    ("alice", "demo12345", "Alice Rahman", "Photography student. Dhaka."),
    ("bob", "demo12345", "Bob Karim", "CSE @ BRACU. Coffee first."),
    ("carol", "demo12345", "Carol Nahar", "Runner, reader, occasional baker."),
]

SAMPLE_POSTS = [
    ("alice", (214, 93, 73), "Golden hour on the rooftop."),
    ("alice", (70, 110, 190), "Blue hour by the river."),
    ("bob", (96, 150, 110), "Morning walk, campus side."),
]

def _image(color):
    from PIL import Image, ImageDraw

    im = Image.new("RGB", (800, 800), color)
    draw = ImageDraw.Draw(im)
    draw.ellipse([220, 220, 580, 580], fill=tuple(min(255, c + 60) for c in color))
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=85)
    return buf.getvalue()

class Command(BaseCommand):
    help = "Seed the database with the team's accounts and sample content (for local SQLite development)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--allow-shared",
            action="store_true",
            help="Permit seeding when DB_ENGINE=mysql (the shared Aiven server). Off by default.",
        )
        parser.add_argument(
            "--accounts-only",
            action="store_true",
            help="Create only the team login accounts, no sample posts/messages/reports.",
        )

    def handle(self, *args, **options):
        engine = settings.DATABASES["default"]["ENGINE"]
        if "sqlite" not in engine and not options["allow_shared"]:
            raise CommandError(
                "Refusing to seed: DB_ENGINE is not sqlite, so this would write to the shared "
                "team database. Re-run with --allow-shared if that is genuinely what you want."
            )

        created_users = self._seed_accounts()
        if not options["accounts_only"]:
            self._seed_content()

        self.stdout.write(self.style.SUCCESS(f"\nSeed complete ({created_users} new account(s))."))
        self.stdout.write("\nOne login page for everyone - /accounts/login/ - your role decides where you land:")
        self.stdout.write("  Developers : Razeen / Afnan / Munia    password 1234")
        self.stdout.write("  Admin      : razeen_admin              password 123")
        if not options["accounts_only"]:
            self.stdout.write("  Users      : alice / bob / carol       password demo12345")

    def _make_user(self, username, password, role, full_name, bio=""):
        user, created = User.objects.get_or_create(
            username=username, defaults={"email": f"{username.lower()}@secureshare.local"}
        )
        if created:
            user.set_password(password)
            user.save()
        profile, _ = Profile.objects.get_or_create(user=user)
        profile.role = role
        profile.full_name = full_name
        if bio:
            profile.bio = bio
        profile.save()
        TwoFactorSettings.objects.get_or_create(user=user)
        return user, created

    def _seed_accounts(self):
        created_count = 0
        self.stdout.write(self.style.MIGRATE_HEADING("Accounts"))
        for username, password, role, full_name in TEAM:
            _, created = self._make_user(username, password, role, full_name)
            created_count += created
            self.stdout.write(f"  {'created' if created else 'exists '}  {username:<14} {role}")
        for username, password, full_name, bio in SAMPLE_USERS:
            _, created = self._make_user(username, password, Role.USER, full_name, bio)
            created_count += created
            self.stdout.write(f"  {'created' if created else 'exists '}  {username:<14} {Role.USER}")
        return created_count

    def _seed_content(self):
        users = {u.username: u for u in User.objects.filter(username__in=[u[0] for u in SAMPLE_USERS])}
        alice, bob, carol = users["alice"], users["bob"], users["carol"]

        self.stdout.write(self.style.MIGRATE_HEADING("\nSocial graph"))
        Friendship.create(alice, bob)
        FriendRequest.objects.get_or_create(sender=carol, receiver=bob)
        self.stdout.write("  alice <-> bob are friends; carol has a pending request to bob")

        self.stdout.write(self.style.MIGRATE_HEADING("\nPosts (encrypted at rest)"))
        for owner_name, color, caption in SAMPLE_POSTS:
            owner = users[owner_name]
            if Post.objects.filter(owner=owner, encrypted_caption__gt="").exists() and Post.objects.filter(
                owner=owner
            ).count() >= sum(1 for o, _, _ in SAMPLE_POSTS if o == owner_name):
                self.stdout.write(f"  exists   {caption}")
                continue
            post = Post(owner=owner)
            encrypt_and_store(post, _image(color), caption)
            post.save()
            other = bob if owner == alice else alice
            Like.objects.get_or_create(user=other, post=post)
            Comment.objects.get_or_create(user=other, post=post, content="Love this one.")
            self.stdout.write(f"  created  {caption}")

        self.stdout.write(self.style.MIGRATE_HEADING("\nMessages (encrypted + MAC'd)"))
        if Message.objects.filter(sender=alice, recipient=bob).exists():
            self.stdout.write("  exists   alice <-> bob thread")
        else:
            for sender, recipient, body in [
                (alice, bob, "Hey! Did you see the new feed?"),
                (bob, alice, "Just looked - looks great."),
                (alice, bob, "Here's the shot from yesterday."),
            ]:
                ciphertext, mac_tag = EncryptionService.encrypt_message(sender, recipient, body)
                Message.objects.create(
                    sender=sender, recipient=recipient, ciphertext=ciphertext, mac_tag=mac_tag
                )
            self.stdout.write("  created  alice <-> bob thread")

        self.stdout.write(self.style.MIGRATE_HEADING("\nReports (one of each kind, for the admin ticket queue)"))
        post = Post.objects.filter(owner=alice).first()
        message = Message.objects.filter(sender=alice, recipient=bob).first()
        pairs = [
            (Report.Kind.POST, {"post": post}, "Wrong location tag."),
            (Report.Kind.USER, {"reported_user": alice}, "Spamming my DMs."),
            (Report.Kind.MESSAGE, {"message": message}, "Unwanted photo."),
        ]
        for kind, target, reason in pairs:
            if not any(target.values()):
                continue
            _, created = Report.objects.get_or_create(
                reporter=bob, kind=kind, defaults={"reason": reason}, **target
            )
            self.stdout.write(f"  {'created' if created else 'exists '}  {kind} report")
