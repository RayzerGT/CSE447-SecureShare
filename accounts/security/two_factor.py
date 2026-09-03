import re

from django.contrib.auth.hashers import check_password, make_password

from accounts.models import SecurityQuestion, TwoFactorSettings

MIN_ANSWER_LENGTH = 2

SECURITY_QUESTIONS = SecurityQuestion.choices


def normalise_answer(answer: str) -> str:
    return re.sub(r"\s+", " ", (answer or "").strip().lower())


def set_security_answer(user, question: str, answer: str) -> TwoFactorSettings:
    if question not in SecurityQuestion.values:
        raise ValueError("unknown security question")

    cleaned = normalise_answer(answer)
    if len(cleaned) < MIN_ANSWER_LENGTH:
        raise ValueError(f"answer must be at least {MIN_ANSWER_LENGTH} characters")

    settings_row, _ = TwoFactorSettings.objects.get_or_create(user=user)
    settings_row.question = question
    settings_row.answer_hash = make_password(cleaned)
    settings_row.method = TwoFactorSettings.Method.SECURITY_QUESTION
    settings_row.is_enabled = True
    settings_row.secret = ""
    settings_row.save(
        update_fields=["question", "answer_hash", "method", "is_enabled", "secret", "updated_at"]
    )
    return settings_row


def disable(user) -> None:
    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    if settings_row is None:
        return
    settings_row.is_enabled = False
    settings_row.question = ""
    settings_row.answer_hash = ""
    settings_row.save(update_fields=["is_enabled", "question", "answer_hash", "updated_at"])


def is_required_for(user) -> bool:
    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    return bool(settings_row and settings_row.is_configured)


def question_text_for(user) -> str:
    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    return settings_row.question_text if settings_row else ""


def verify_answer(user, submitted_answer: str) -> bool:
    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    if settings_row is None or not settings_row.is_configured:
        return False

    cleaned = normalise_answer(submitted_answer)
    if not cleaned:
        return False
    return check_password(cleaned, settings_row.answer_hash)
