"""
accounts/management/commands/seed_demo.py
Shared tooling (lives under accounts/ because Django discovers management
commands from installed apps; it is not account-specific).

    python manage.py seed_demo

Fills a fresh database with the team's standard accounts plus enough sample
content to actually exercise the UI (friends, posts, likes, comments, DMs,
one report of each kind). Without this, a brand-new SQLite file has zero
users, so you can't even log in to look at anything.

Safe to re-run: everything is get_or_create'd, so it tops up what's missing
rather than duplicating.

By default this REFUSES to run against the shared MySQL server - seeding the
database the whole team (and the demonstration) relies on should be a
deliberate act, so it needs --allow-shared.
"""

import io

from django.conf import settings
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand, CommandError

from accounts.models import Profile, Role, TwoFactorSettings
from messaging.models import Message
from moderation.models import Report
from posts.models import Post
from social.models import Comment, FriendRequest, Friendship, Like

# username, password, role, full name
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
    """A small solid-colour JPEG, so the repo needs no binary sample assets."""
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
        self.stdout.write("\nLog in at /accounts/login/ (standard users) or /portal/login/ (admin & developer):")
        self.stdout.write("  Developers : Razeen / Afnan / Munia    password 1234")
        self.stdout.write("  Admin      : razeen_admin              password 123")
        if not options["accounts_only"]:
            self.stdout.write("  Users      : alice / bob / carol       password demo12345")

    # -- accounts ---------------------------------------------------------

    def _make_user(self, username, password, role, full_name, bio=""):
        user, created = User.objects.get_or_create(
            username=username, defaults={"email": f"{username.lower()}@secureshare.local"}
        )
        if created:
            # TODO(Afnan Satter): once accounts/security/hashing.py is wired in,
            # this should go through the from-scratch hash+salt pipeline, same
            # as accounts/views.py::register().
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

    # -- content ----------------------------------------------------------

    def _seed_content(self):
        users = {u.username: u for u in User.objects.filter(username__in=[u[0] for u in SAMPLE_USERS])}
        alice, bob, carol = users["alice"], users["bob"], users["carol"]

        self.stdout.write(self.style.MIGRATE_HEADING("\nSocial graph"))
        Friendship.create(alice, bob)
        FriendRequest.objects.get_or_create(sender=carol, receiver=bob)
        self.stdout.write("  alice <-> bob are friends; carol has a pending request to bob")

        self.stdout.write(self.style.MIGRATE_HEADING("\nPosts"))
        for owner_name, color, caption in SAMPLE_POSTS:
            owner = users[owner_name]
            if Post.objects.filter(owner=owner, caption=caption).exists():
                self.stdout.write(f"  exists   {caption}")
                continue
            post = Post(owner=owner, caption=caption)
            post.image.save(f"seed_{owner_name}_{abs(hash(caption)) % 10000}.jpg", ContentFile(_image(color)), save=True)
            other = bob if owner == alice else alice
            Like.objects.get_or_create(user=other, post=post)
            Comment.objects.get_or_create(user=other, post=post, content="Love this one.")
            self.stdout.write(f"  created  {caption}")

        self.stdout.write(self.style.MIGRATE_HEADING("\nMessages"))
        if Message.objects.filter(sender=alice, recipient=bob).exists():
            self.stdout.write("  exists   alice <-> bob thread")
        else:
            Message.objects.create(sender=alice, recipient=bob, plaintext_body="Hey! Did you see the new feed?")
            Message.objects.create(sender=bob, recipient=alice, plaintext_body="Just looked - looks great.")
            photo = Message(sender=alice, recipient=bob, plaintext_body="Here's the shot from yesterday.")
            photo.image.save("seed_dm.jpg", ContentFile(_image((150, 110, 190))), save=True)
            self.stdout.write("  created  alice <-> bob thread (with a photo)")

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
