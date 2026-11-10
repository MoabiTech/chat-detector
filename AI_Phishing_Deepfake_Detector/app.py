# Enhanced AI Phishing & Deepfake Detector
# Complete implementation with all required features

import streamlit as st
import hashlib
import io
import re
import time
import json
import mimetypes
import os
import ipaddress
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from datetime import datetime, timezone
from urllib.parse import urlparse
from PIL import Image
from utils.input_safety import (
    MAX_TEXT_INPUT_BYTES,
    UploadValidationError,
    privacy_safe_report,
    text_input_size_bytes,
    validate_upload,
    validate_upload_size,
)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
PORTAL_CHAT_URL = os.environ.get('PORTAL_CHAT_URL', 'http://127.0.0.1:5001')
PORTAL_SESSION_API = f'{PORTAL_CHAT_URL}/api/session'


def portal_session_request(action: str, token: str):
    request = Request(
        f'{PORTAL_SESSION_API}/{action}',
        data=json.dumps({'token': token}).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urlopen(request, timeout=3) as response:
            result = json.loads(response.read().decode('utf-8'))
    except HTTPError as error:
        if error.code == 401:
            return None
        raise RuntimeError(f'The sign-in service returned HTTP {error.code}.') from error
    except (URLError, TimeoutError) as error:
        raise RuntimeError('The local sign-in service is unavailable.') from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError('The local sign-in service returned an invalid response.') from error
    if not isinstance(result, dict):
        raise RuntimeError('The local sign-in service returned an invalid response.')
    return result


@st.cache_resource
def get_ocr_engine():
    from utils.experimental_models import load_ocr_engine

    return load_ocr_engine()


@st.cache_resource
def get_email_classifier():
    from utils.experimental_models import load_email_classifier

    return load_email_classifier()


@st.cache_resource
def get_image_classifier():
    from utils.experimental_models import load_image_classifier

    return load_image_classifier()


@st.cache_resource
def get_audio_classifier():
    from utils.experimental_models import load_audio_classifier

    return load_audio_classifier()


@st.cache_resource
def get_logo_detector():
    from utils.logo_detector import LogoDetector

    return LogoDetector(os.path.join(APP_ROOT, 'logos'))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_email_input(sender: str, subject: str, body: str) -> str:
    email_input = json.dumps(
        {'sender': sender, 'subject': subject, 'body': body},
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':'),
    ).encode('utf-8')
    return sha256_bytes(email_input)


class _HtmlTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {'script', 'style'}:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag.lower() in {'script', 'style'} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if not self.hidden_depth and data.strip():
            self.text_parts.append(data.strip())


def _extract_eml(data: bytes) -> tuple[str, str, str]:
    message = BytesParser(policy=policy.default).parsebytes(data)
    body_parts = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == 'attachment':
            continue
        content_type = part.get_content_type()
        if content_type not in {'text/plain', 'text/html'}:
            continue
        try:
            body = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            body = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
        if not isinstance(body, str):
            continue
        if content_type == 'text/html':
            parser = _HtmlTextExtractor()
            parser.feed(body)
            body = '\n'.join(parser.text_parts)
        if body.strip():
            body_parts.append(body.strip())
    return str(message.get('From', '')), str(message.get('Subject', '')), '\n'.join(body_parts)


def scan_email(
    text: str,
    sender: str = '',
    subject: str = '',
    ml_result: dict | None = None,
):
    start_time = time.perf_counter()
    content = f'{subject}\n{sender}\n{text}'.strip()
    lower = content.lower()
    findings = []
    score = 0
    
    checks = [
        (r'\b(urgent|immediately|act now|final warning|account suspended|verify your account|expire|limited time)\b',
         'Urgency or account-pressure wording', 15),
        (r'\b(password|login credentials|one-time password|otp|verification code|pin|ssn|social security)\b',
         'Requests sensitive authentication/personal information', 20),
        (r'\b(wire transfer|bank account|payment|gift card|crypto|bitcoin|change of bank details|remittance)\b',
         'Payment or financial-action wording', 18),
        (r'\b(click here|open the attachment|enable macros|download now|click link|confirm now)\b',
         'Call to click, download, or enable content', 12),
        (r'\b(prize|winner|claim your reward|you have won|lottery|congratulations.*won)\b',
         'Prize or reward lure', 12),
        (r'\b(ceo|director|manager|lecturer|administrator|hr|payroll|finance|it support)\b',
         'Authority/personnel impersonation - verify independently', 6),
        (r'\b(update.*details|re-verify|confirm.*identity)\b',
         'Identity verification request', 10),
        (r'\b(within (?:\d+|one|two|three|four|five|six|seven|eight|nine|ten) hours?|'
         r'by (?:close of business|end of day|midnight)|final notice|legal action|'
         r'permanently (?:suspend|disable|close))\b',
         'Threat or deadline pressure', 12),
        (r'\b(do not tell|keep this confidential|do not discuss|bypass (?:the )?usual process)\b',
         'Secrecy or process-bypass instruction', 14),
        (r'\b(mfa|multi.factor|authenticator app|approve the sign.in|push notification)\b',
         'Possible authentication-prompt manipulation', 12),
        (r'\b(scan (?:the )?(?:qr|code)|qr code|quick response code)\b',
         'QR-code instruction may conceal a destination URL', 8),
        (r'\b(invoice attached|payment overdue|past.due invoice|refund available|'
         r'failed delivery|missed package|voicemail attached)\b',
         'Common delivery, invoice, or refund lure', 8),
    ]
    for pattern, label, points in checks:
        if re.search(pattern, lower):
            findings.append({'indicator': label, 'points': points})
            score += points
    
    raw_urls = re.findall(
        r'(?<![@\w])(?:https?://|www\.)[^\s<>\])\"\'\}]+'
        r'|(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
        r'(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?::\d+)?(?:/[^\s<>\])\"\'\}]*)?',
        content,
        flags=re.I,
    )
    urls = []
    for raw in raw_urls:
        cleaned = raw.rstrip('.,;:)]}')
        if cleaned in urls:
            continue
        urls.append(cleaned)
        try:
            parsed = urlparse(cleaned if re.match(r'^https?://', cleaned, re.I) else 'http://' + cleaned)
            host = (parsed.hostname or '').lower()
        except ValueError:
            findings.append({'indicator': f'Malformed URL could not be parsed: {cleaned}', 'points': 8})
            score += 8
            continue
        if host:
            try:
                ipaddress.ip_address(host)
                is_ip_address = True
            except ValueError:
                is_ip_address = False
            if is_ip_address:
                findings.append({'indicator': f'URL uses IP address (suspicious): {cleaned}', 'points': 18})
                score += 18
            if parsed.username or parsed.password:
                findings.append({'indicator': f'URL contains misleading embedded credentials: {cleaned}', 'points': 16})
                score += 16
            if 'xn--' in host or any(ord(c) > 127 for c in host):
                findings.append({'indicator': f'URL contains punycode/internationalized domain: {cleaned}', 'points': 18})
                score += 18
            if len(host) > 40:
                findings.append({'indicator': f'Unusually long URL host ({len(host)} chars): {host}', 'points': 7})
                score += 7
            if re.search(r'\.(tk|ml|ga|cf|gq|top|xyz)$', host):
                findings.append({'indicator': f'Suspicious top-level domain: {host}', 'points': 10})
                score += 10
    
    if sender:
        from email.utils import parseaddr

        display_name, address = parseaddr(sender)
        sender_domain = address.rsplit('@', 1)[-1].lower() if '@' in address else ''
        free_email_domains = {
            'gmail.com', 'googlemail.com', 'outlook.com', 'outlook.co.uk',
            'hotmail.com', 'hotmail.co.uk', 'yahoo.com', 'yahoo.co.uk',
            'aol.com', 'icloud.com', 'proton.me', 'protonmail.com',
        }
        if sender_domain in free_email_domains and re.search(
            r'\b(ceo|director|payroll|finance|bank|wire|transfer|urgent|confidential)\b', lower
        ):
            findings.append({'indicator': 'Free email provider used with business/financial urgency - high impersonation risk', 'points': 15})
            score += 15
        try:
            if display_name and sender_domain and re.search(
                r'\b(ceo|director|manager|lecturer|administrator|hr|payroll|finance|it support)\b',
                display_name,
                re.I,
            ):
                display_token = re.sub(r'[^a-z0-9]', '', display_name.lower())
                domain_token = re.sub(r'[^a-z0-9]', '', sender_domain.split('.')[0])
                if display_token and display_token not in domain_token:
                    findings.append({
                        'indicator': 'Display name claims an authority role but sender domain does not identify that role',
                        'points': 10,
                    })
                    score += 10
        except (TypeError, ValueError):
            findings.append({'indicator': 'Sender header could not be parsed reliably', 'points': 3})
            score += 3
    
    if re.search(r'\b(copy|paste).*link|link.*below', lower):
        findings.append({'indicator': 'Instructions to copy/paste link (bypass security)', 'points': 8})
        score += 8
    
    score = min(score, 100)
    if score >= 60:
        level = 'High Risk - Strong phishing indicators'
    elif score >= 35:
        level = 'Medium Risk - Suspicious indicators present'
    elif score >= 15:
        level = 'Low-Medium Risk - Some concerns'
    else:
        level = 'Low Risk - Few indicators found'
    
    if not findings:
        findings.append({'indicator': 'No configured rule matched. This does not prove the email is safe.', 'points': 0})
    recommendations = [
        'Do not open links or attachments until you verify the request through a known, independent contact channel.',
        'Never provide passwords, one-time codes, or approve unexpected authentication prompts.',
    ]
    if urls:
        recommendations.append('Inspect each listed URL using your organization-approved security tools; this detector did not visit any URL.')
    if score >= 35:
        recommendations.append('Report this message to your institution’s IT/security team and follow its incident process.')
    if ml_result is not None:
        recommendations.append('Treat the experimental model estimate as supporting evidence only; the rule-based risk score remains separate.')
        if ml_result.get('input_characters_truncated') or ml_result.get('input_tokens_truncated'):
            recommendations.append(
                'The experimental classifier analyzed only a truncated portion of the email; rule-based checks scanned the complete supplied text.'
            )
    
    return {
        'module': 'Rule-based email screening with optional experimental ML',
        'risk_score': score,
        'risk_level': level,
        'assessment_status': (
            'Suspicious indicators present; not independently confirmed.'
            if score
            else 'Inconclusive: no configured rule matched.'
        ),
        'uncertainty': (
            'Rule-based scores are triage signals, not calibrated probabilities. '
            'A low score does not prove that a message is safe.'
        ),
        'findings': findings,
        'urls_found': urls,
        'model_status': (
            'Experimental local transformer classifier run'
            if ml_result is not None
            else 'Optional local transformer classifier not run; transparent rules active'
        ),
        'ml_classification': ml_result,
        'detection_methods': [
            'Urgency, threats, and deadline analysis',
            'Credential and MFA-prompt request detection',
            'Financial, delivery, QR-code, and secrecy lures',
            'URL/IP/punycode/embedded-credential analysis',
            'Sender display-name and free-provider heuristics',
        ],
        'limitations': 'Rules can miss sophisticated attacks and may flag legitimate messages. Always verify sender through official channels independently.',
        'recommendations': recommendations,
        'analysis_time_seconds': round(time.perf_counter() - start_time, 6)
    }


def media_metadata(
    data: bytes,
    filename: str,
    mime: str = '',
    *,
    run_ocr: bool = False,
    run_models: bool = False,
):
    validate_upload(data, filename)
    start_time = time.perf_counter()
    info = {
        'filename': filename,
        'mime_type': mimetypes.guess_type(filename)[0] or 'application/octet-stream',
        'size_bytes': len(data),
        'size_mib': round(len(data) / (1024 * 1024), 4),
        'sha256_before': sha256_bytes(data),
        'integrity_check': 'Original upload is held in memory only; SHA-256 is compared before and after inspection.',
        'processing_timestamp': datetime.now(timezone.utc).isoformat()
    }
    ext = os.path.splitext(filename)[1].lower()
    extracted_text = ''
    qr_payloads = []
    try:
        if ext in ['.txt', '.eml']:
            sender = ''
            subject = ''
            if ext == '.eml':
                sender, subject, text = _extract_eml(data)
                info['email_sender'] = sender
                info['email_subject'] = subject
            else:
                text = data.decode('utf-8-sig', errors='replace')
            info['media_type'] = 'text'
            info['character_count'] = len(text)
            ml_result = None
            if run_models:
                try:
                    from utils.experimental_models import classify_email

                    tokenizer, model, torch = get_email_classifier()
                    ml_result = classify_email(text, tokenizer, model, torch)
                    info['experimental_phishing_classification'] = ml_result
                except Exception:
                    info['phishing_model_error'] = 'Optional local email model could not run; details omitted.'
            info['email_analysis'] = scan_email(text, sender, subject, ml_result)
            info['metadata_note'] = 'Text is analyzed using transparent rules and optional experimental local classification. No links are opened.'
        elif ext in ['.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tif', '.tiff']:
            info['deepfake_classifier_status'] = 'not run'
            image = Image.open(io.BytesIO(data))
            info['media_type'] = 'image'
            info['image_format'] = image.format
            info['dimensions'] = f'{image.width} x {image.height}'
            info['mode'] = image.mode
            info['metadata_note'] = 'Image metadata and optional OCR/logo similarity are inspection signals; they do not establish authenticity.'
            try:
                logo_results = get_logo_detector().detect(data)
                logo_errors = [result for result in logo_results if 'error' in result]
                info['logo_detection'] = [result for result in logo_results if 'error' not in result]
                info['known_logo_count'] = len(get_logo_detector().logo_hashes)
                info['copied_logo_indicator'] = bool(info['logo_detection'])
                info['logo_detection_status'] = (
                    'error' if logo_errors else
                    'no known logo references configured' if not info['known_logo_count'] else
                    'similarity checked'
                )
                if logo_errors:
                    info['logo_detection_error'] = 'One or more configured logo references could not be inspected.'
            except Exception:
                info['logo_detection_status'] = 'error'
                info['logo_detection_error'] = 'Local logo comparison could not run; details omitted.'

            try:
                from utils.experimental_models import decode_qr_codes

                qr_payloads = decode_qr_codes(image)
                info['qr_payloads'] = qr_payloads
            except Exception:
                info['qr_detection_error'] = 'Local QR inspection could not run; details omitted.'

            if run_ocr:
                try:
                    from utils.experimental_models import extract_text_from_image

                    ocr_result = extract_text_from_image(image, get_ocr_engine())
                    info['ocr'] = ocr_result
                    info['ocr']['engine'] = 'RapidOCR using ONNX Runtime'
                    extracted_text = ocr_result['text']
                except Exception:
                    info['ocr_error'] = 'Local OCR could not run; details omitted.'

            if run_models:
                try:
                    from utils.experimental_models import classify_images

                    processor, model, torch = get_image_classifier()
                    info['experimental_ai_classification'] = classify_images(
                        [image], processor, model, torch
                    )[0]
                    info['deepfake_classifier_status'] = 'completed'
                except Exception:
                    info['deepfake_model_error'] = 'Optional local image model could not run; details omitted.'
                    info['deepfake_classifier_status'] = 'error'
                
        elif ext in ['.wav', '.flac', '.ogg', '.aif', '.aiff', '.m4a']:
            info['deepfake_classifier_status'] = 'not run'
            import soundfile as sf

            info['media_type'] = 'audio'
            audio_data = data
            source_duration = None
            if ext == '.m4a':
                try:
                    from utils.experimental_models import decode_m4a_audio

                    audio_data, source_duration = decode_m4a_audio(data)
                except Exception:
                    raise UploadValidationError(
                        'M4A audio could not be decoded by the available local decoder.'
                    ) from None

            if audio_data is not None:
                audio_info = sf.info(io.BytesIO(audio_data))
                info['duration_seconds'] = round(
                    source_duration if source_duration is not None else audio_info.duration,
                    4,
                )
                info['sample_rate_hz'] = audio_info.samplerate
                info['channels'] = audio_info.channels
                info['audio_format'] = (
                    'M4A (decoded to WAV for inspection)' if ext == '.m4a' else audio_info.format
                )
                info['audio_subtype'] = audio_info.subtype
                info['metadata_note'] = (
                    'M4A audio is decoded locally to mono 16 kHz PCM for inspection. '
                    'The experimental classifier analyzes at most 20 seconds; metadata and model '
                    'estimates do not establish authenticity.'
                    if ext == '.m4a' else
                    'Audio metadata does not establish authenticity. The optional experimental classifier '
                    'analyzes at most 20 seconds and is not a validated forensic verdict.'
                )
            if run_models and audio_data is not None:
                try:
                    from utils.experimental_models import classify_audio

                    processor, model, torch = get_audio_classifier()
                    classification = classify_audio(audio_data, processor, model, torch)
                    if source_duration is not None:
                        classification['duration_omitted_seconds'] = round(
                            max(0, source_duration - classification['duration_analyzed_seconds']),
                            3,
                        )
                    info['experimental_ai_classification'] = classification
                    info['deepfake_classifier_status'] = 'completed'
                except Exception:
                    info['deepfake_model_error'] = 'Optional local audio model could not run; details omitted.'
                    info['deepfake_classifier_status'] = 'error'
        elif ext in ['.mp4', '.mov', '.avi', '.mkv', '.webm']:
            info['deepfake_classifier_status'] = 'not run'
            info['media_type'] = 'video'
            info['metadata_note'] = 'Video analysis samples frames; it does not evaluate temporal consistency and is not a validated video-forensics verdict.'
            try:
                from utils.experimental_models import extract_video_frames

                frames, video_metadata = extract_video_frames(data, ext)
                info.update(video_metadata)
                info['sampled_frame_count'] = len(frames)
            except Exception:
                raise UploadValidationError(
                    "The video is invalid or cannot be decoded by the available local tools."
                ) from None
            if frames and run_ocr:
                try:
                    from utils.experimental_models import extract_text_from_image

                    ocr_engine = get_ocr_engine()
                    ocr_results = [
                        extract_text_from_image(frame, ocr_engine)
                        for frame in frames
                    ]
                    extracted_text = '\n'.join(
                        result['text'] for result in ocr_results if result['text']
                    )
                    info['ocr'] = {
                        'text': extracted_text,
                        'engine': 'RapidOCR using ONNX Runtime',
                        'sampled_frame_detections': ocr_results,
                    }
                except Exception:
                    info['ocr_error'] = 'Local OCR could not run; details omitted.'
            if frames:
                try:
                    from utils.experimental_models import decode_qr_codes

                    for frame in frames:
                        qr_payloads.extend(decode_qr_codes(frame))
                    qr_payloads = list(dict.fromkeys(qr_payloads))
                    info['qr_payloads'] = qr_payloads
                except Exception:
                    info['qr_detection_error'] = 'Local QR inspection could not run; details omitted.'
            if frames and run_models:
                try:
                    from utils.experimental_models import classify_images

                    processor, model, torch = get_image_classifier()
                    frame_results = classify_images(frames, processor, model, torch)
                    if frame_results:
                        info['experimental_frame_classification'] = {
                            'model': frame_results[0]['model'],
                            'model_revision': frame_results[0]['model_revision'],
                            'sample_count': len(frame_results),
                            'mean_fake_probability': round(
                                sum(item['fake_probability'] for item in frame_results) / len(frame_results),
                                6,
                            ),
                            'frame_results': frame_results,
                            'limitations': (
                                'Image model applied independently to sampled frames; this is not temporal video analysis. '
                                + frame_results[0]['limitations']
                            ),
                        }
                        info['deepfake_classifier_status'] = 'completed'
                except Exception:
                    info['deepfake_model_error'] = 'Optional local video model could not run; details omitted.'
                    info['deepfake_classifier_status'] = 'error'
        else:
            info['media_type'] = 'other'
            info['metadata_note'] = f'File type {ext} not in supported categories for detailed inspection.'
    except UploadValidationError:
        raise
    except Exception:
        info['inspection_error'] = 'The file could not be parsed by the available local inspectors.'
        info['metadata_note'] = 'File could not be parsed by available inspectors.'
    
    if extracted_text:
        info['ocr_email_analysis'] = scan_email(extracted_text)
        info['ocr_email_analysis']['recommendations'].append(
            'OCR can misread text or miss content; manually review the original image/video as well.'
        )
    if qr_payloads:
        info['qr_email_analysis'] = scan_email('\n'.join(qr_payloads))
        info['qr_email_analysis']['recommendations'].append(
            'QR contents are decoded for inspection only; the detector did not open or follow them.'
        )
    info['deepfake_result'] = (
        'EXPERIMENTAL MODEL ESTIMATE - Not an authenticity verdict'
        if info.get('experimental_ai_classification') or info.get('experimental_frame_classification')
        else 'NOT DETERMINED - Experimental model inference was not run or is unavailable'
    )
    info['ai_detection_status'] = (
        'Experimental local model was run; independent validation is not established'
        if info.get('experimental_ai_classification') or info.get('experimental_frame_classification')
        else 'Model inference not run'
    )
    info['warning'] = (
        'Model scores are estimates, not proof. A low score does not prove the media is authentic, '
        'and a high score does not prove it is manipulated.'
    )
    suspicious_text_signal = any(
        info.get(key, {}).get('risk_score', 0) > 0
        for key in ('email_analysis', 'ocr_email_analysis', 'qr_email_analysis')
    )
    info['assessment_status'] = (
        'Suspicious indicators present; not independently confirmed.'
        if suspicious_text_signal else
        'Experimental model estimate only; outcome is unconfirmed.'
        if info.get('experimental_ai_classification') or info.get('experimental_frame_classification') else
        'Inconclusive: no validated media classification was produced.'
    )
    info['uncertainty'] = (
        'Model outputs are experimental and uncalibrated for this application. '
        'Metadata, OCR, logo similarity, and heuristic indicators do not establish authenticity or manipulation.'
    )
    info['sha256_after'] = sha256_bytes(data)
    info['integrity_verified'] = info['sha256_before'] == info['sha256_after']
    info['recommendations'] = [
        'Verify the sender and context through an independent, trusted channel before acting.',
        'Do not treat metadata, logo similarity, OCR, or experimental model scores as proof of authenticity.',
    ]
    if info.get('ocr_email_analysis', {}).get('risk_score', 0) >= 35:
        info['recommendations'].append(
            'OCR found suspicious email wording; inspect the message and any destination using approved security tools.'
        )
    if info.get('qr_email_analysis', {}).get('risk_score', 0) >= 35:
        info['recommendations'].append(
            'A decoded QR payload contains suspicious indicators; do not open it and report it through approved channels.'
        )
    if info.get('integrity_verified'):
        info['recommendations'].append(
            'Preserve the original file and its SHA-256 hash if incident response or formal evidence handling is needed.'
        )
    info['analysis_time_seconds'] = round(time.perf_counter() - start_time, 6)
    return info

def render_report(report):
    return json.dumps(privacy_safe_report(report), indent=2, ensure_ascii=False)


def is_loopback_bind_address(address: str | None) -> bool:
    """Only allow addresses that resolve to the local machine."""
    return str(address or '').strip().lower() in {'127.0.0.1', 'localhost', '::1'}

def clear_media_report():
    st.session_state.pop('media_report', None)
    st.session_state.pop('run_media_models', None)
    st.session_state.pop('run_image_classifier', None)
    st.session_state.pop('run_video_classifier', None)
    st.session_state.pop('run_other_media_classifier', None)


def should_run_media_classifier_by_default(filename: str) -> bool:
    extension = os.path.splitext(filename)[1].lower()
    return extension in {
        '.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tif', '.tiff',
        '.mp4', '.mov', '.avi', '.mkv', '.webm',
        '.wav', '.flac', '.ogg', '.aif', '.aiff', '.m4a',
    }


def render_integrity_status(integrity_verified: bool) -> None:
    if integrity_verified:
        st.success('SHA-256 is unchanged after analysis; uploaded bytes were not modified.')
    else:
        st.error('Integrity verification failed: before/after SHA-256 values differ.')


def render_project_evidence() -> None:
    st.subheader('Part II | Evidence and presentation')
    st.caption(
        'Use this panel to explain what the local system does and what has actually been measured. '
        'Classifier outputs are experimental estimates, not verified verdicts.'
    )

    st.markdown('#### Performance acceptance targets')
    performance_columns = st.columns(5)
    performance_columns[0].metric('Email/text', '≤ 15 s', 'warm-analysis target')
    performance_columns[1].metric('Image', '≤ 15 s', 'warm-analysis target')
    performance_columns[2].metric('Audio', '≤ 15 s', 'warm-analysis target')
    performance_columns[3].metric('Video', '≤ 15 s', 'warm-analysis target')
    performance_columns[4].metric('Report generation', '≤ 5 s', 'after analysis')
    st.info(
        'The 15-second target applies to analysis after selected models have loaded. First-time model '
        'downloads and initialization are measured separately and may take longer. These are requested '
        'targets, not verified results; target-device measurements remain outstanding.'
    )
    st.caption(
        'Upload limits: text 1 MiB, image 10 MiB, audio 20 MiB, video 50 MiB. '
        'The application rejects unsupported or oversized uploads with a user-facing explanation.'
    )
    with st.expander('Previously measured local baseline (not the target device)'):
        st.markdown(
            '- Suspicious email: 0.0093 s average across 5 runs.\n'
            '- Image: 0.428 s average for a 1.47 MiB PNG.\n'
            '- Audio: 0.0394 s average for a 1 MiB WAV.\n'
            '- Video: 1.663 s average for a 1.09 MiB AVI.\n'
            '- Largest successful samples: 5.63 MiB image, 5 MiB audio, and 5.52 MiB video.'
        )
    st.caption(
        'Baseline measurements were made on Windows 11 with an Intel Core i5-1135G7, 8 logical processors, '
        'and 11.79 GiB RAM on 2026-11-07, with optional OCR and model inference disabled (3 media runs, '
        '5 email runs). They do not establish warm-model or target-device performance. The encrypted chat '
        'file-transfer limit is 10 MiB.'
    )

    with st.expander('AI models, file formats, and extra detection steps', expanded=True):
        st.markdown(
            '- **Email:** explainable rules plus an optional local DistilBERT phishing classifier.\n'
            '- **Image/video:** optional experimental SigLIP classification; video uses up to eight sampled frames.\n'
            '- **Audio:** optional experimental Wav2Vec2 classification; up to 20 seconds are analyzed.\n'
            '- **Text extraction:** RapidOCR screens image/video text; QR payloads are extracted and screened.\n'
            '- **Formats:** TXT/EML; JPG/JPEG, PNG, WEBP, BMP, TIF/TIFF; WAV, FLAC, OGG, AIF/AIFF, M4A; '
            'MP4, MOV, AVI, MKV, WEBM.\n'
            '- **Safe handling:** suspicious URLs and QR destinations are listed but never opened. '
            'Original media bytes are not rewritten; SHA-256 hashes are compared before and after inspection.\n'
            '- **Limitations:** model accuracy has not been independently validated here. OCR can miss text, '
            'and frame-based video analysis does not measure temporal consistency.'
        )

    st.markdown('#### End-to-end encrypted chat')
    st.markdown(
        'The local chat uses SQLite-backed password accounts, browser-persisted non-exportable RSA-OAEP and '
        'ECDSA keys, out-of-band fingerprint pinning, and signed AES-256-GCM message/file envelopes. '
        'Tests cover account authentication, account-key binding, signatures, and tamper rejection.'
    )
    st.warning(
        'Local-only prototype: compare each peer fingerprint over an independent trusted channel. There is '
        'no recovery, forward secrecy, HTTPS, metadata protection, or safety if a compromised server changes '
        'client code. Public-cloud deployment is not enabled. Start '
        '`e2ee_chat/start_server.bat` before opening the local chat.'
    )
    st.link_button('Return to app choices and chat', PORTAL_CHAT_URL)

    st.markdown('#### Lessons learnt | Part I and Part II')
    st.markdown(
        '- **Part I:** identify assets and threats systematically; assess likelihood and impact; select and '
        'test controls before accepting residual risk.\n'
        '- **Part II:** combine explainable checks with cautious AI estimates, verify high-impact requests '
        'through a separate trusted channel, preserve file integrity, and report real performance and limitations.'
    )

    st.markdown('#### Live presentation checklist')
    st.markdown(
        '- **Audibility:** speak clearly, face the audience, and avoid reading every slide verbatim.\n'
        '- **Confidence:** explain both the evidence and the detector’s limitations honestly.\n'
        '- **Dress code:** agree on neat, appropriate attire as a team before presentation day.\n'
        '- **Teamwork:** assign the demo, technical explanation, results, and Q&A roles; support hand-offs.\n'
        '- **Questions and answers:** prepare to explain model choices, measured runtimes, file-size limits, '
        'false positives, hash checks, and why the chat is a classroom demo.'
    )
    st.caption('Presentation items are reminders for the team to demonstrate; they are not app-generated scores.')


def render_email_workspace() -> None:
    st.subheader('Email threat analysis')
    st.caption('Screen a suspicious message with explainable rules and an optional local model.')
    sender = st.text_input('Sender address (optional)', key='email_sender')
    subject = st.text_input('Subject (optional)', key='email_subject')
    email_text = st.text_area(
        'Paste email text (maximum 1 MiB)',
        height=220,
        max_chars=MAX_TEXT_INPUT_BYTES,
        key='email_body',
    )
    run_email_model = st.checkbox(
        'Run experimental local email classifier (downloads about 270 MB on first use)',
        value=True,
        key='run_email_model',
    )
    if st.button('Analyze email', type='primary', key='analyze_email'):
        if not email_text.strip() and not subject.strip():
            st.error('Enter an email subject or message before analysis.')
        elif text_input_size_bytes(sender, subject, email_text) > MAX_TEXT_INPUT_BYTES:
            st.error('Email text, subject, and sender must not exceed 1 MiB combined (UTF-8).')
        else:
            processing_start = time.perf_counter()
            email_hash_before = sha256_email_input(sender, subject, email_text)
            ml_result = None
            ml_error = None
            if run_email_model:
                try:
                    with st.spinner('Loading local email classifier and analyzing message...'):
                        from utils.experimental_models import classify_email

                        tokenizer, model, torch = get_email_classifier()
                        ml_result = classify_email(
                            f'{subject}\n{sender}\n{email_text}', tokenizer, model, torch
                        )
                except Exception:
                    ml_error = 'Optional local classifier could not run; details omitted.'
            analysis = scan_email(email_text, sender, subject, ml_result)
            email_hash_after = sha256_email_input(sender, subject, email_text)
            email_report = {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'sender': sender,
                'subject': subject,
                'analysis': analysis,
                'ml_model_error': ml_error,
                'sha256_before': email_hash_before,
                'sha256_after': email_hash_after,
                'integrity_verified': email_hash_before == email_hash_after,
                'integrity_check': (
                    'SHA-256 covers the submitted sender, subject, and body; '
                    'the original text is not included in the downloadable report.'
                ),
            }
            email_report['analysis_wall_time_seconds'] = round(
                time.perf_counter() - processing_start, 6
            )
            report_start = time.perf_counter()
            render_report(email_report)
            email_report['report_generation_time_seconds'] = round(
                time.perf_counter() - report_start, 6
            )
            email_report['total_processing_time_seconds'] = round(
                email_report['analysis_wall_time_seconds']
                + email_report['report_generation_time_seconds'],
                6,
            )
            st.session_state.email_report = email_report

    email_report = st.session_state.get('email_report')
    if not email_report:
        return
    analysis = email_report['analysis']
    st.metric('Risk score', f"{analysis['risk_score']} / 100", analysis['risk_level'])
    render_integrity_status(email_report['integrity_verified'])
    if email_report.get('ml_model_error'):
        st.error(f"Optional classifier could not run: {email_report['ml_model_error']}")
    elif analysis.get('ml_classification'):
        ml = analysis['ml_classification']
        st.metric(
            'Experimental model estimate',
            ml['model_estimate'],
            f"{ml['phishing_probability']:.1%} phishing-like probability",
        )
        st.caption(ml['limitations'])
    st.subheader('Findings')
    for finding in analysis['findings']:
        st.text(f"{finding['indicator']} (+{finding['points']})")
    st.caption('Extracted URLs are listed only; the detector never opens them.')
    for url in analysis['urls_found']:
        st.code(url, language=None)
    st.caption(analysis['limitations'])
    st.subheader('Recommendations')
    for recommendation in analysis.get('recommendations', []):
        st.markdown(f'- {recommendation}')
    st.download_button(
        'Download email report (JSON)',
        data=render_report(email_report),
        file_name='email_analysis_report.json',
        mime='application/json',
    )


def render_file_workspace(
    title: str,
    uploader_key: str,
    file_types: list[str],
) -> None:
    st.subheader(title)
    uploaded_file = st.file_uploader(
        'Select a file for local inspection',
        type=file_types,
        key=uploader_key,
        on_change=clear_media_report,
    )
    st.caption(
        'Local-only limits: text 1 MiB, images 10 MiB, audio 20 MiB, and supported video 50 MiB. '
        'Unsupported, oversized, or invalid content is rejected before analysis.'
    )
    extension = (
        os.path.splitext(uploaded_file.name)[1].lower()
        if uploaded_file is not None else ''
    )
    is_image = extension in {'.jpg', '.jpeg', '.png', '.webp', '.bmp', '.tif', '.tiff'}
    is_video = extension in {'.mp4', '.mov', '.avi', '.mkv', '.webm'}
    is_audio = extension in {'.wav', '.flac', '.ogg', '.aif', '.aiff', '.m4a'}
    is_visual_media = is_image or is_video
    if is_visual_media:
        run_ocr = st.checkbox(
            'Extract text from image/video frames and screen it for phishing (downloads OCR weights on first use)',
            value=True,
            key='run_media_ocr',
        )
    else:
        run_ocr = False
    if uploaded_file is not None:
        model_label = (
            'Run experimental deepfake image classifier (downloads about 355 MiB on first use)'
            if is_image else
            'Run experimental deepfake video classifier on sampled frames (downloads about 355 MiB on first use)'
            if is_video else
            'Run experimental deepfake audio classifier (downloads about 360 MiB on first use)'
            if is_audio else
            'Run experimental local classifier (downloads model weights on first use)'
        )
        model_key = (
            'run_image_classifier' if is_image else
            'run_video_classifier' if is_video else
            'run_other_media_classifier'
        )
        run_media_models = st.checkbox(
            model_label,
            value=should_run_media_classifier_by_default(uploaded_file.name),
            key=model_key,
        )
        if is_visual_media:
            st.caption(
                'This experimental classifier estimates synthetic-like imagery; it cannot prove authenticity. '
                'The first run downloads about 355 MiB and requires internet access.'
            )
        elif is_audio:
            st.caption(
                'This experimental Wav2Vec2 classifier estimates AI-generated versus human speech. '
                'It analyzes at most the first 20 seconds. The first model load downloads about 360 MiB '
                'and may take a few minutes on CPU; it cannot prove authenticity.'
            )
    else:
        run_media_models = False

    if st.button(
        'Inspect file',
        type='primary',
        disabled=uploaded_file is None,
        key='inspect_file',
    ) and uploaded_file is not None:
        try:
            validate_upload_size(uploaded_file.name, uploaded_file.size)
            with st.spinner('Inspecting the file locally...'):
                media_report = media_metadata(
                    uploaded_file.getvalue(),
                    uploaded_file.name,
                    uploaded_file.type or '',
                    run_ocr=run_ocr,
                    run_models=run_media_models,
                )
            report_start = time.perf_counter()
            render_report(media_report)
            media_report['report_generation_time_seconds'] = round(
                time.perf_counter() - report_start, 6
            )
            media_report['total_processing_time_seconds'] = round(
                media_report['analysis_time_seconds']
                + media_report['report_generation_time_seconds'],
                6,
            )
            st.session_state.media_report = media_report
        except UploadValidationError as validation_error:
            st.error(str(validation_error))

    media_report = st.session_state.get('media_report')
    if not media_report:
        return
    st.text(f"File: {media_report['filename']}")
    st.text(f"Type: {media_report.get('media_type', 'unknown')}")
    st.text(f"Size: {media_report['size_mib']} MiB")
    if media_report.get('inspection_error'):
        st.error('File inspection failed; details are included in the JSON report.')
        st.text(media_report['inspection_error'])
    for error_key, error_title in (
        ('ocr_error', 'OCR could not run'),
        ('deepfake_model_error', 'Experimental media model could not run'),
        ('phishing_model_error', 'Experimental email model could not run'),
        ('qr_detection_error', 'QR code detection could not run'),
        ('video_inspection_error', 'Video could not be inspected'),
    ):
        if media_report.get(error_key):
            st.error(f"{error_title}: {media_report[error_key]}")
    if media_report.get('qr_payloads'):
        st.subheader('Decoded QR payloads (not opened)')
        for payload in media_report['qr_payloads']:
            st.code(payload, language=None)
    if media_report.get('ocr', {}).get('text'):
        st.subheader('Text found by OCR')
        st.text(media_report['ocr']['text'])
    for analysis_key, heading, metric_label in (
        ('email_analysis', 'Email screening', 'Email rule score'),
        ('ocr_email_analysis', 'OCR phishing screening', 'OCR text rule score'),
        ('qr_email_analysis', 'QR payload screening', 'QR payload rule score'),
    ):
        email_analysis = media_report.get(analysis_key, {})
        if email_analysis:
            st.subheader(heading)
            st.metric(
                metric_label,
                f"{email_analysis['risk_score']} / 100",
                email_analysis['risk_level'],
            )
            for finding in email_analysis['findings']:
                st.text(f"{finding['indicator']} (+{finding['points']})")
            if email_analysis['urls_found']:
                st.caption('URLs extracted from the message are listed only and are never opened.')
                for url in email_analysis['urls_found']:
                    st.code(url, language=None)
            for recommendation in email_analysis.get('recommendations', []):
                st.markdown(f'- {recommendation}')
    if media_report.get('experimental_ai_classification'):
        classification = media_report['experimental_ai_classification']
        probability = classification.get(
            'fake_probability',
            classification.get('phishing_probability'),
        )
        if probability is not None:
            st.metric(
                'Experimental model score',
                classification['model_estimate'],
                f"{probability:.1%} model score",
            )
            st.caption(classification['limitations'])
    if media_report.get('experimental_phishing_classification'):
        classification = media_report['experimental_phishing_classification']
        st.metric(
            'Experimental email model estimate',
            classification['model_estimate'],
            f"{classification['phishing_probability']:.1%} phishing-like probability",
        )
        st.caption(classification['limitations'])
    if media_report.get('experimental_frame_classification'):
        classification = media_report['experimental_frame_classification']
        st.metric(
            'Experimental sampled-frame score',
            f"{classification['mean_fake_probability']:.1%} synthetic-like",
            f"{classification['sample_count']} frames sampled",
        )
        st.caption(classification['limitations'])
    if media_report.get('logo_detection_status'):
        st.caption(
            f"Logo similarity: {media_report['logo_detection_status']} "
            f"({media_report.get('known_logo_count', 0)} reference logos)"
        )
    if media_report.get('media_type') == 'image':
        if media_report.get('experimental_ai_classification'):
            st.success('Experimental AI image classification completed.')
        elif media_report.get('deepfake_model_error'):
            st.error(
                'AI image classification failed; no synthetic-media estimate is available. '
                'See the model error above and retry after checking network access/model setup.'
            )
        else:
            st.warning(
                'No AI deepfake estimate was produced. Enable the experimental image classifier '
                'before inspecting the file.'
            )
        if media_report.get('logo_detection_status') == 'no known logo references configured':
            st.info('Copied-logo matching is inactive because no reference logos are configured.')
    elif media_report.get('media_type') == 'audio':
        if media_report.get('experimental_ai_classification'):
            st.success('Experimental AI audio classification completed.')
        elif media_report.get('deepfake_model_error'):
            st.error(
                'AI audio classification failed; no synthetic-audio estimate is available. '
                'See the model error above and check network access/model setup.'
            )
        else:
            st.warning(
                'No AI audio estimate was produced. Enable the experimental audio classifier '
                'before inspecting the file.'
            )
    render_integrity_status(media_report.get('integrity_verified', False))
    st.subheader('Recommendations')
    for recommendation in media_report.get('recommendations', []):
        st.markdown(f'- {recommendation}')
    st.info(media_report['warning'])
    st.json(privacy_safe_report(media_report))
    st.download_button(
        'Download file inspection report (JSON)',
        data=render_report(media_report),
        file_name='media_inspection_report.json',
        mime='application/json',
    )


def run_app():
    if not is_loopback_bind_address(st.get_option('server.address')):
        st.error(
            'Local-only mode is required. Set Streamlit server.address to 127.0.0.1 '
            'and restart; non-loopback listeners are not supported.'
        )
        st.stop()
    st.set_page_config(page_title='AI Phishing & Deepfake Detector', page_icon='🔍', layout='wide')
    session_token = st.query_params.get('session')
    if not isinstance(session_token, str) or not session_token:
        st.error('Sign in through the Local-First Threat Analysis app before opening the detector.')
        st.link_button('Go to sign in', PORTAL_CHAT_URL)
        st.stop()
    try:
        portal_session = portal_session_request('validate', session_token)
    except RuntimeError as error:
        st.error(str(error))
        st.link_button('Return to sign in', PORTAL_CHAT_URL)
        st.stop()
    if not portal_session or not portal_session.get('success'):
        st.error('Your app session is invalid or expired. Sign in again to continue.')
        st.link_button('Return to sign in', PORTAL_CHAT_URL)
        st.stop()

    with open(os.path.join(APP_ROOT, 'static', 'cybersecurity.css'), encoding='utf-8') as stylesheet:
        st.markdown(f'<style>{stylesheet.read()}</style>', unsafe_allow_html=True)
    st.sidebar.markdown(
        '<div class="dashboard-brand"><span>LOCAL-FIRST</span><strong>THREAT ANALYSIS</strong></div>',
        unsafe_allow_html=True,
    )
    st.sidebar.caption('WORKSPACE')
    section = st.sidebar.radio(
        'Workspace',
        ['Overview', 'Email', 'Media', 'Files', 'Chat', 'About'],
        key='dashboard_section',
        label_visibility='collapsed',
        on_change=clear_media_report,
    )
    media_category = None
    if section == 'Media':
        st.sidebar.caption('MEDIA TYPE')
        media_category = st.sidebar.radio(
            'Media type',
            ['Audios', 'Images', 'Videos'],
            key='dashboard_media_category',
            label_visibility='collapsed',
            on_change=clear_media_report,
        )
    st.sidebar.divider()
    st.sidebar.markdown('**LOCAL SESSION**')
    st.sidebar.caption(f"Signed in as {portal_session['username']}")
    st.sidebar.caption('Analysis runs on this device.')
    st.sidebar.link_button(
        'App choices and chat',
        PORTAL_CHAT_URL,
        use_container_width=True,
    )
    if st.sidebar.button('Sign out', use_container_width=True):
        try:
            revoked_session = portal_session_request('revoke', session_token)
        except RuntimeError as error:
            st.sidebar.error(str(error))
        else:
            if revoked_session and revoked_session.get('success'):
                st.query_params.clear()
                st.rerun()
            st.sidebar.error(
                (revoked_session or {}).get('error', 'Could not end the app session.')
            )

    st.markdown(
        '<div class="dashboard-eyebrow">SECURITY WORKSPACE / LOCAL ANALYSIS</div>'
        '<h1 class="dashboard-title">Phishing &amp; deepfake analysis</h1>'
        '<p class="dashboard-description">Review suspicious email, media, and files in one local workspace.</p>',
        unsafe_allow_html=True,
    )
    if section == 'Overview':
        email_report = st.session_state.get('email_report')
        media_report = st.session_state.get('media_report')
        latest_email = (
            f"{email_report['analysis']['risk_score']} / 100"
            if email_report else 'Waiting for analysis'
        )
        latest_file = (
            media_report.get('media_type', 'File').title()
            if media_report else 'Waiting for inspection'
        )
        status_columns = st.columns(3)
        status_columns[0].metric('Email screening', latest_email)
        status_columns[1].metric('Media & files', latest_file)
        status_columns[2].metric('Workspace', 'Local', 'Session verified')
        st.markdown('### Analysis services')
        service_columns = st.columns(2)
        with service_columns[0]:
            st.markdown(
                '<div class="service-card"><span class="service-state">READY</span>'
                '<h3>Email</h3><p>Screen sender details, message wording, and suspicious links.</p></div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div class="service-card"><span class="service-state">READY</span>'
                '<h3>Media</h3><p>Inspect audio, images, and video with optional local models.</p></div>',
                unsafe_allow_html=True,
            )
        with service_columns[1]:
            st.markdown(
                '<div class="service-card"><span class="service-state">READY</span>'
                '<h3>Files</h3><p>Inspect supported TXT, EML, image, audio, and video evidence.</p></div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div class="service-card"><span class="service-state">AVAILABLE</span>'
                '<h3>Encrypted chat</h3><p>Open the separate end-to-end encrypted chat workspace.</p></div>',
                unsafe_allow_html=True,
            )
        st.caption(
            'Scores and model outputs are triage signals only. A low score does not prove a message or file is safe.'
        )
    elif section == 'Email':
        render_email_workspace()
    elif section == 'Media':
        media_types = {
            'Audios': ['wav', 'flac', 'ogg', 'aif', 'aiff', 'm4a'],
            'Images': ['jpg', 'jpeg', 'png', 'webp', 'bmp', 'tif', 'tiff'],
            'Videos': ['mp4', 'mov', 'avi', 'mkv', 'webm'],
        }
        category_title = media_category.rstrip('s').title()
        render_file_workspace(
            f'Inspect {category_title.lower()}',
            f'media_{media_category.lower()}_file',
            media_types[media_category],
        )
    elif section == 'Files':
        render_file_workspace(
            'Inspect a file',
            'general_file',
            [
                'txt', 'eml', 'jpg', 'jpeg', 'png', 'webp', 'bmp', 'tif', 'tiff',
                'wav', 'flac', 'ogg', 'aif', 'aiff', 'm4a',
                'mp4', 'mov', 'avi', 'mkv', 'webm',
            ],
        )
    elif section == 'Chat':
        st.markdown(
            '<div class="service-card"><span class="service-state">LOCAL</span>'
            '<h3>End-to-end encrypted chat</h3>'
            '<p>Continue to your signed-in chat portal to open encrypted conversations.</p></div>',
            unsafe_allow_html=True,
        )
        st.link_button('Open end-to-end encrypted chat', PORTAL_CHAT_URL, type='primary')
        st.caption('Chat opens in the portal. Your detector sign-in session remains active.')
    else:
        render_project_evidence()

if __name__ == '__main__':
    run_app()
