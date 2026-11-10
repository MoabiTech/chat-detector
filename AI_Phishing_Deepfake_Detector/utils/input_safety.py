"""Local upload validation for the detector.

The browser-supplied MIME type is deliberately not trusted. Accepted files are
checked against their extension, size, and a parser or container signature
before the detector processes them.
"""

from __future__ import annotations

import io
import os
import re
import warnings
from email import policy
from email.parser import BytesParser

from PIL import Image

MIB = 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000

EXTENSION_CATEGORIES = {
    ".txt": "text",
    ".eml": "text",
    ".jpg": "image",
    ".jpeg": "image",
    ".png": "image",
    ".webp": "image",
    ".bmp": "image",
    ".tif": "image",
    ".tiff": "image",
    ".wav": "audio",
    ".flac": "audio",
    ".ogg": "audio",
    ".aif": "audio",
    ".aiff": "audio",
    ".m4a": "audio",
    ".mp4": "video",
    ".mov": "video",
    ".avi": "video",
    ".mkv": "video",
    ".webm": "video",
}

CATEGORY_LIMITS = {
    "text": 1 * MIB,
    "image": 10 * MIB,
    "audio": 20 * MIB,
    "video": 50 * MIB,
}
MAX_TEXT_INPUT_BYTES = CATEGORY_LIMITS["text"]

_IMAGE_FORMATS = {
    ".jpg": {"JPEG"},
    ".jpeg": {"JPEG"},
    ".png": {"PNG"},
    ".webp": {"WEBP"},
    ".bmp": {"BMP"},
    ".tif": {"TIFF"},
    ".tiff": {"TIFF"},
}


class UploadValidationError(ValueError):
    """Raised when an upload is unsupported, oversized, or invalid."""


def text_input_size_bytes(*values: str) -> int:
    """Return UTF-8 payload size for pasted email fields."""
    if any(not isinstance(value, str) for value in values):
        raise UploadValidationError("Email text fields must be valid text.")
    return sum(len(value.encode("utf-8")) for value in values)


def _extension(filename: str) -> str:
    safe_name = os.path.basename(str(filename).replace("\\", "/"))
    return os.path.splitext(safe_name)[1].lower()


def validate_upload_size(filename: str, size_bytes: int) -> str:
    """Check an upload's declared size before reading its bytes."""
    extension = _extension(filename)
    category = EXTENSION_CATEGORIES.get(extension)
    if category is None:
        raise UploadValidationError(
            "Unsupported file type. Choose a supported TXT/EML, image, audio, or video file."
        )
    if not isinstance(size_bytes, int) or size_bytes < 0:
        raise UploadValidationError("The uploaded file size could not be verified.")
    limit = CATEGORY_LIMITS[category]
    if size_bytes > limit:
        limit_mib = limit // MIB
        raise UploadValidationError(
            f"{category.title()} files must be no larger than {limit_mib} MiB."
        )
    return category


def _validate_text(data: bytes, extension: str) -> None:
    if b"\x00" in data:
        raise UploadValidationError("Text files must not contain binary data.")
    if extension == ".txt":
        try:
            data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise UploadValidationError("Text files must use valid UTF-8 encoding.") from exc
    else:
        try:
            message = BytesParser(policy=policy.default).parsebytes(data)
        except (ValueError, UnicodeError) as exc:
            raise UploadValidationError("The EML file could not be parsed.") from exc
        if not message.items():
            raise UploadValidationError("The EML file does not contain valid message headers.")


def _validate_image(data: bytes, extension: str) -> None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            image = Image.open(io.BytesIO(data))
            if image.format not in _IMAGE_FORMATS[extension]:
                raise UploadValidationError(
                    "The image content does not match its filename extension."
                )
            if image.width <= 0 or image.height <= 0:
                raise UploadValidationError("The image has invalid dimensions.")
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise UploadValidationError(
                    f"Images may not exceed {MAX_IMAGE_PIXELS:,} pixels."
                )
            image.verify()
    except UploadValidationError:
        raise
    except Exception as exc:
        raise UploadValidationError(
            "The image is invalid, truncated, or too large to inspect safely."
        ) from exc


def _has_audio_signature(data: bytes, extension: str) -> bool:
    if extension == ".wav":
        return (
            len(data) >= 12
            and data[:4] in {b"RIFF", b"RF64"}
            and data[8:12] == b"WAVE"
        )
    if extension == ".flac":
        return data.startswith(b"fLaC")
    if extension == ".ogg":
        return data.startswith(b"OggS")
    if extension in {".aif", ".aiff"}:
        return len(data) >= 12 and data[:4] == b"FORM" and data[8:12] in {
            b"AIFF",
            b"AIFC",
        }
    if extension == ".m4a":
        return len(data) >= 12 and data[4:8] == b"ftyp"
    return False


def _validate_audio(data: bytes, extension: str) -> None:
    if not _has_audio_signature(data, extension):
        raise UploadValidationError(
            "The audio content does not match its filename extension."
        )
    if extension == ".m4a":
        # The local FFmpeg decoder performs full parsing during analysis.
        return
    try:
        import soundfile as sf

        audio_info = sf.info(io.BytesIO(data))
        if audio_info.frames <= 0 or audio_info.channels <= 0 or audio_info.samplerate <= 0:
            raise UploadValidationError("The audio file has no readable samples.")
    except UploadValidationError:
        raise
    except Exception as exc:
        raise UploadValidationError(
            "The audio file is invalid or cannot be decoded by the available local tools."
        ) from exc


def _validate_video_signature(data: bytes, extension: str) -> None:
    if extension in {".mp4", ".mov"}:
        valid = len(data) >= 12 and data[4:8] == b"ftyp"
    elif extension == ".avi":
        valid = len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"AVI "
    else:
        # Matroska and WebM share the EBML header; OpenCV validates the actual stream.
        valid = data.startswith(b"\x1a\x45\xdf\xa3")
    if not valid:
        raise UploadValidationError(
            "The video content does not match its filename extension."
        )


def validate_upload(data: bytes, filename: str) -> str:
    """Validate type, category limit, and basic content before analysis."""
    if not isinstance(data, bytes):
        raise UploadValidationError("The uploaded file could not be read as bytes.")
    category = validate_upload_size(filename, len(data))
    if not data:
        raise UploadValidationError("The uploaded file is empty.")

    extension = _extension(filename)
    if category == "text":
        _validate_text(data, extension)
    elif category == "image":
        _validate_image(data, extension)
    elif category == "audio":
        _validate_audio(data, extension)
    elif category == "video":
        _validate_video_signature(data, extension)
    return category


def privacy_safe_report(report: dict) -> dict:
    """Return a JSON-ready copy with uploaded content and identifiers removed."""
    def sanitize(value, key: str = ""):
        normalized_key = key.lower()
        if normalized_key == "filename":
            extension = _extension(str(value))
            if extension not in EXTENSION_CATEGORIES:
                extension = ""
            return f"[uploaded file]{extension}" if extension else "[uploaded file]"
        if normalized_key in {
            "sender",
            "email_sender",
            "subject",
            "email_subject",
            "extracted_text",
        }:
            return "[redacted]"
        if normalized_key in {"urls_found", "qr_payloads"}:
            return {"count": len(value) if isinstance(value, (list, tuple)) else 0,
                    "values_redacted": True}
        if normalized_key.endswith("_error") or normalized_key == "ml_model_error":
            return "Details omitted to protect local data."
        if normalized_key == "text" and isinstance(value, str):
            return {
                "character_count": len(value),
                "content_redacted": True,
            }
        if isinstance(value, dict):
            return {child_key: sanitize(child_value, child_key)
                    for child_key, child_value in value.items()}
        if isinstance(value, (list, tuple)):
            return [sanitize(item) for item in value]
        if isinstance(value, str):
            # URL-bearing finding text can otherwise disclose private destinations.
            value = re.sub(
                r"(?i)\b(?:https?://|www\.)[^\s<>'\"]+",
                "[URL redacted]",
                value,
            )
            value = re.sub(
                r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
                "[email redacted]",
                value,
            )
            value = re.sub(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                "[IP redacted]",
                value,
            )
            value = re.sub(
                r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59})"
                r"(?::\d+)?(?:/[^\s<>'\"]*)?",
                "[domain redacted]",
                value,
            )
            return value
        return value

    return sanitize(report)
