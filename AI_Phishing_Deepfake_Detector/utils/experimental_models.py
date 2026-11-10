"""Optional, locally-run OCR and experimental classification models."""

from __future__ import annotations

import io
import os
import re
import subprocess
import tempfile
from fractions import Fraction
from typing import Any

import numpy as np
from PIL import Image

EMAIL_MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
EMAIL_MODEL_REVISION = "6724dec17360ab1f6450553f1d950404f66a5dde"
IMAGE_MODEL_ID = "prithivMLmods/deepfake-detector-model-v1"
IMAGE_MODEL_REVISION = "c5cb24c6a159dd2b57ca15c6a1065bd0ce8fa380"
AUDIO_MODEL_ID = "Hemgg/Deepfake-audio-detection"
AUDIO_MODEL_REVISION = "0d75271368ef2c7efd14831dc503c431f6aab0eb"

EXPERIMENTAL_MODEL_LIMITATIONS = (
    "These third-party models are experimental research classifiers. Their published "
    "metrics are self-reported, were not independently reproduced here, and do not "
    "guarantee performance on new people, institutions, languages, generators, or attacks."
)


def load_ocr_engine() -> Any:
    from rapidocr import RapidOCR

    return RapidOCR()


def extract_text_from_image(image: Image.Image, engine: Any) -> dict[str, Any]:
    output = engine(np.asarray(image.convert("RGB")))
    if not output or not getattr(output, "txts", None):
        return {"text": "", "detections": []}

    detections = []
    boxes = getattr(output, "boxes", None)
    scores = getattr(output, "scores", None)
    for index, raw_text in enumerate(output.txts):
        text = str(raw_text).strip()
        if text:
            detections.append({
                "text": text,
                "confidence": (
                    round(float(scores[index]), 4)
                    if scores is not None and index < len(scores)
                    else None
                ),
                "box": (
                    np.asarray(boxes[index]).tolist()
                    if boxes is not None and index < len(boxes)
                    else None
                ),
            })
    return {
        "text": "\n".join(item["text"] for item in detections),
        "detections": detections,
        "elapsed_seconds": round(float(getattr(output, "elapse", 0.0)), 6),
    }


def decode_qr_codes(image: Image.Image) -> list[str]:
    import cv2

    grayscale = cv2.cvtColor(np.asarray(image.convert("RGB")), cv2.COLOR_RGB2GRAY)
    detector = cv2.QRCodeDetector()
    payloads = []
    detected_points = None
    multiple_decode_succeeded = False
    supports_multi = hasattr(detector, "detectAndDecodeMulti")
    if supports_multi:
        (
            multiple_decode_succeeded,
            decoded,
            detected_points,
            _straight,
        ) = detector.detectAndDecodeMulti(grayscale)
        if multiple_decode_succeeded:
            payloads.extend(str(value).strip() for value in decoded if value and value.strip())
    if not payloads and (
        not supports_multi or multiple_decode_succeeded or detected_points is not None
    ):
        decoded, _points, _straight = detector.detectAndDecode(grayscale)
        if decoded and decoded.strip():
            payloads.append(decoded.strip())
    return list(dict.fromkeys(payloads))


def load_email_classifier() -> tuple[Any, Any, Any]:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        EMAIL_MODEL_ID,
        revision=EMAIL_MODEL_REVISION,
        trust_remote_code=False,
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        EMAIL_MODEL_ID,
        revision=EMAIL_MODEL_REVISION,
        trust_remote_code=False,
    ).to("cpu")
    model.eval()
    return tokenizer, model, torch


def classify_email(text: str, tokenizer: Any, model: Any, torch: Any) -> dict[str, Any]:
    max_characters = 20000
    model_text = text[:max_characters]
    token_count = len(tokenizer(model_text, add_special_tokens=True, truncation=False)["input_ids"])
    inputs = tokenizer(
        model_text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
    )
    with torch.inference_mode():
        probabilities = torch.softmax(model(**inputs).logits[0], dim=-1).tolist()

    # The model card describes four classes, with classes 1 and 3 representing
    # phishing URLs and classes 0 and 2 representing legitimate email/URLs.
    labels = [
        "legitimate_email",
        "phishing_url",
        "legitimate_url",
        "phishing_url_alt",
    ]
    if len(probabilities) != len(labels):
        raise ValueError(f"Expected four email model classes; received {len(probabilities)}.")
    phishing_probability = probabilities[1] + probabilities[3]
    return {
        "model": EMAIL_MODEL_ID,
        "model_revision": EMAIL_MODEL_REVISION,
        "license": "Apache-2.0",
        "source_url": f"https://huggingface.co/{EMAIL_MODEL_ID}",
        "input_characters": len(model_text),
        "input_characters_truncated": len(text) > max_characters,
        "input_tokens_before_model_limit": token_count,
        "input_tokens_truncated": token_count > 512,
        "class_probabilities": {
            label: round(float(probability), 6)
            for label, probability in zip(labels, probabilities)
        },
        "phishing_probability": round(float(phishing_probability), 6),
        "model_estimate": "phishing-like" if phishing_probability >= 0.5 else "benign-like",
        "limitations": EXPERIMENTAL_MODEL_LIMITATIONS,
        "reported_metrics": {
            "accuracy_percent": 99.58,
            "f1_percent": 99.579,
            "source": "Model card; self-reported and not independently verified",
        },
    }


def load_image_classifier() -> tuple[Any, Any, Any]:
    import torch
    from transformers import AutoImageProcessor, AutoModelForImageClassification

    processor = AutoImageProcessor.from_pretrained(
        IMAGE_MODEL_ID,
        revision=IMAGE_MODEL_REVISION,
        trust_remote_code=False,
    )
    model = AutoModelForImageClassification.from_pretrained(
        IMAGE_MODEL_ID,
        revision=IMAGE_MODEL_REVISION,
        trust_remote_code=False,
    ).to("cpu")
    model.eval()
    return processor, model, torch


def classify_images(
    images: list[Image.Image], processor: Any, model: Any, torch: Any
) -> list[dict[str, Any]]:
    if not images:
        return []
    inputs = processor(images=[image.convert("RGB") for image in images], return_tensors="pt")
    with torch.inference_mode():
        probabilities = torch.softmax(model(**inputs).logits, dim=-1).tolist()

    fake_index = next(
        (index for index, label in model.config.id2label.items() if "fake" in label.lower()),
        None,
    )
    real_index = next(
        (index for index, label in model.config.id2label.items() if "real" in label.lower()),
        None,
    )
    if fake_index is None or real_index is None:
        raise ValueError("Image model labels do not identify both fake and real classes.")
    return [
        {
            "model": IMAGE_MODEL_ID,
            "model_revision": IMAGE_MODEL_REVISION,
            "license": "Apache-2.0",
            "source_url": f"https://huggingface.co/{IMAGE_MODEL_ID}",
            "fake_probability": round(float(row[fake_index]), 6),
            "real_probability": round(float(row[real_index]), 6),
            "model_estimate": "synthetic-like" if row[fake_index] >= 0.5 else "real-like",
            "limitations": EXPERIMENTAL_MODEL_LIMITATIONS,
            "reported_metrics": {
                "accuracy_percent": 94.44,
                "source": "Model card; self-reported on its evaluation split and not independently verified",
            },
        }
        for row in probabilities
    ]


def extract_video_frames(
    data: bytes, suffix: str, max_frames: int = 8
) -> tuple[list[Image.Image], dict[str, Any]]:
    import cv2

    temp_path = None
    capture = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
            temp_file.write(data)
            temp_path = temp_file.name
        capture = cv2.VideoCapture(temp_path)
        if not capture.isOpened():
            raise ValueError("OpenCV could not decode this video.")
        frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
        if frame_count <= 0:
            raise ValueError("Video has no readable frames.")
        fps = capture.get(cv2.CAP_PROP_FPS)
        metadata = {
            "frame_count": frame_count,
            "fps": round(float(fps), 3) if fps and fps > 0 else None,
            "dimensions": (
                f"{int(capture.get(cv2.CAP_PROP_FRAME_WIDTH))} x "
                f"{int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT))}"
            ),
            "duration_seconds": round(frame_count / fps, 4) if fps and fps > 0 else None,
            "codec_info": "Decoded with OpenCV",
        }
        positions = np.linspace(0, frame_count - 1, num=min(max_frames, frame_count), dtype=int)
        frames = []
        for position in np.unique(positions):
            capture.set(cv2.CAP_PROP_POS_FRAMES, int(position))
            success, frame = capture.read()
            if success:
                frames.append(Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)))
        if not frames:
            raise ValueError("OpenCV opened the video but could not read any frames.")
        return frames, metadata
    finally:
        if capture is not None:
            capture.release()
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError as exc:
                raise OSError(f"Could not remove temporary video file {temp_path}: {exc}") from exc


def load_audio_classifier() -> tuple[Any, Any, Any]:
    import torch
    from transformers import AutoFeatureExtractor, AutoModelForAudioClassification

    cache_dir = os.environ.get("DETECTOR_AUDIO_MODEL_CACHE")
    processor = AutoFeatureExtractor.from_pretrained(
        AUDIO_MODEL_ID,
        revision=AUDIO_MODEL_REVISION,
        trust_remote_code=False,
        cache_dir=cache_dir,
    )
    model = AutoModelForAudioClassification.from_pretrained(
        AUDIO_MODEL_ID,
        revision=AUDIO_MODEL_REVISION,
        trust_remote_code=False,
        cache_dir=cache_dir,
    ).to("cpu")
    model.eval()
    return processor, model, torch


def decode_m4a_audio(data: bytes, max_seconds: int = 20) -> tuple[bytes, float]:
    import imageio_ffmpeg
    import soundfile as sf

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            suffix=".m4a",
            delete=False,
            dir=os.environ.get("DETECTOR_AUDIO_TEMP_DIR"),
        ) as temp_file:
            temp_path = temp_file.name
            temp_file.write(data)

        command = [
            imageio_ffmpeg.get_ffmpeg_exe(),
            "-hide_banner",
            "-loglevel",
            "info",
            "-i",
            temp_path,
            "-map",
            "0:a:0",
            "-vn",
            "-ac",
            "1",
            "-ar",
            "16000",
            "-t",
            str(max_seconds),
            "-c:a",
            "pcm_s16le",
            "-f",
            "wav",
            "pipe:1",
        ]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=120,
        )
        if result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"FFmpeg could not decode this M4A audio: {detail[-1000:]}")
        if not result.stdout:
            raise ValueError("FFmpeg produced no audio samples for this M4A file.")
    finally:
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError as cleanup_error:
                raise OSError(
                    f"Could not remove temporary M4A file {temp_path}: {cleanup_error}"
                ) from cleanup_error

    duration_match = re.search(
        rb"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)",
        result.stderr,
    )
    if duration_match:
        hours, minutes, seconds = duration_match.groups()
        duration_seconds = int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    else:
        duration_seconds = float(sf.info(io.BytesIO(result.stdout)).duration)
    return result.stdout, duration_seconds


def classify_audio(
    data: bytes, processor: Any, model: Any, torch: Any, max_seconds: int = 20
) -> dict[str, Any]:
    import soundfile as sf
    from scipy.signal import resample_poly

    audio, sample_rate = sf.read(io.BytesIO(data), dtype="float32", always_2d=True)
    if sample_rate <= 0 or audio.size == 0:
        raise ValueError("Audio data is empty or has an invalid sample rate.")
    mono = np.mean(audio, axis=1)
    original_duration = len(mono) / sample_rate
    if sample_rate != 16000:
        ratio = Fraction(16000, sample_rate)
        mono = resample_poly(mono, ratio.numerator, ratio.denominator).astype(np.float32)
    analyzed = mono[: max_seconds * 16000]
    chunk_length = 10 * 16000
    chunks = [analyzed[start : start + chunk_length] for start in range(0, len(analyzed), chunk_length)]

    chunk_probs = []
    for chunk in chunks:
        inputs = processor(chunk, sampling_rate=16000, return_tensors="pt", padding=True)
        with torch.inference_mode():
            chunk_probs.append(torch.softmax(model(**inputs).logits[0], dim=-1).tolist())
    mean_probs = np.mean(chunk_probs, axis=0).tolist()

    fake_index = next(
        (index for index, label in model.config.id2label.items() if "ai" in label.lower() or "fake" in label.lower()),
        None,
    )
    real_index = next(
        (index for index, label in model.config.id2label.items() if "human" in label.lower() or "real" in label.lower()),
        None,
    )
    if fake_index is None or real_index is None:
        raise ValueError("Audio model labels do not identify both synthetic and human classes.")
    fake_probability = float(mean_probs[fake_index])
    return {
        "model": AUDIO_MODEL_ID,
        "model_revision": AUDIO_MODEL_REVISION,
        "license": "Apache-2.0",
        "source_url": f"https://huggingface.co/{AUDIO_MODEL_ID}",
        "fake_probability": round(fake_probability, 6),
        "real_probability": round(float(mean_probs[real_index]), 6),
        "model_estimate": "synthetic-like" if fake_probability >= 0.5 else "human-like",
        "chunks_analyzed": len(chunks),
        "duration_analyzed_seconds": round(len(analyzed) / 16000, 3),
        "duration_omitted_seconds": round(max(0, original_duration - max_seconds), 3),
        "limitations": EXPERIMENTAL_MODEL_LIMITATIONS,
        "reported_metrics": {
            "accuracy_percent": 95.45,
            "source": "Model card; self-reported evaluation with dataset details not independently verified",
        },
    }
