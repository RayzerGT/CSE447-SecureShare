import io

from PIL import Image, ImageOps

FULL_MAX_EDGE = 1080
THUMBNAIL_MAX_EDGE = 640
FULL_QUALITY = 85
THUMBNAIL_QUALITY = 80
AVATAR_MAX_EDGE = 320
ATTACHMENT_MAX_EDGE = 1080
FULL_BYTE_BUDGET = 200_000
THUMBNAIL_BYTE_BUDGET = 70_000
AVATAR_BYTE_BUDGET = 40_000
ATTACHMENT_BYTE_BUDGET = 200_000
QUALITY_FLOOR = 45
CONTENT_TYPE = "image/jpeg"


def _encode(image: Image.Image, max_edge: int, quality: int, byte_budget: int) -> bytes:
    if image.mode not in ("RGB", "L"):
        image = image.convert("RGB")
    image.thumbnail((max_edge, max_edge), Image.LANCZOS)

    while True:
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=quality, optimize=True, progressive=True)
        encoded = buffer.getvalue()
        if len(encoded) <= byte_budget or quality <= QUALITY_FLOOR:
            return encoded
        quality -= 10


def prepare_upload(raw_bytes: bytes) -> tuple:
    with Image.open(io.BytesIO(raw_bytes)) as opened:
        opened.load()
        upright = ImageOps.exif_transpose(opened) or opened
        full = _encode(upright.copy(), FULL_MAX_EDGE, FULL_QUALITY, FULL_BYTE_BUDGET)
        thumbnail = _encode(upright.copy(), THUMBNAIL_MAX_EDGE, THUMBNAIL_QUALITY, THUMBNAIL_BYTE_BUDGET)
    return full, thumbnail


def prepare_single(raw_bytes: bytes, max_edge: int, byte_budget: int, quality: int = FULL_QUALITY) -> bytes:
    with Image.open(io.BytesIO(raw_bytes)) as opened:
        opened.load()
        upright = ImageOps.exif_transpose(opened) or opened
        return _encode(upright.copy(), max_edge, quality, byte_budget)


def prepare_avatar(raw_bytes: bytes) -> bytes:
    return prepare_single(raw_bytes, AVATAR_MAX_EDGE, AVATAR_BYTE_BUDGET)


def prepare_attachment(raw_bytes: bytes) -> bytes:
    return prepare_single(raw_bytes, ATTACHMENT_MAX_EDGE, ATTACHMENT_BYTE_BUDGET)
