from django.apps import AppConfig


class SocialConfig(AppConfig):
    """
    Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

    Likes and comments on posts. (No input-sanitization/XSS sub-feature -
    that was only in the team's own project-ideas proposal, not the graded
    requirements doc, and has been dropped from scope.)
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "social"
