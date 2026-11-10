import io
import csv
import json
import os
import tempfile
import unittest
import wave
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from PIL import Image
from streamlit.testing.v1 import AppTest

from app import (
    is_loopback_bind_address,
    media_metadata,
    render_integrity_status,
    render_report,
    scan_email,
    sha256_bytes,
    sha256_email_input,
    should_run_media_classifier_by_default,
)
from scripts.evaluate_labeled_data import evaluate_csv, evaluate_rows
from scripts.benchmark import analysis_timing_summary, model_execution_status
from utils.input_safety import (
    CATEGORY_LIMITS,
    MIB,
    UploadValidationError,
    privacy_safe_report,
    text_input_size_bytes,
    validate_upload,
    validate_upload_size,
)
from utils.experimental_models import (
    classify_audio,
    classify_email,
    decode_qr_codes,
    extract_text_from_image,
)


class EmailAnalysisTests(unittest.TestCase):
    def test_synthetic_email_dataset_covers_benign_and_phishing_cases(self):
        dataset_path = (
            Path(__file__).parent / 'sample_files' / 'email_classification_cases.csv'
        )
        with dataset_path.open(encoding='utf-8', newline='') as dataset_file:
            rows = list(csv.DictReader(dataset_file))

        self.assertEqual(len(rows), 20)
        self.assertEqual(
            {
                label: sum(row['label'] == label for row in rows)
                for label in ('benign', 'phishing')
            },
            {'benign': 10, 'phishing': 10},
        )
        self.assertEqual(
            {row['source'] for row in rows},
            {'synthetic'},
        )
        self.assertEqual(len({row['id'] for row in rows}), len(rows))
        self.assertTrue(all(
            'http://' not in row['body'].lower()
            and 'https://' not in row['body'].lower()
            for row in rows
        ))
        self.assertTrue(all(None not in row for row in rows))

        for row in rows:
            with self.subTest(case=row['id']):
                result = scan_email(row['body'], row['sender'], row['subject'])
                prediction = 'phishing' if result['risk_score'] >= 35 else 'benign'
                self.assertEqual(prediction, row['label'], result['findings'])

    def test_flags_phishing_indicators_without_opening_links(self):
        result = scan_email(
            'Urgent: verify your password now at http://192.0.2.1/account'
        )

        self.assertGreaterEqual(result['risk_score'], 35)
        self.assertTrue(result['urls_found'])
        self.assertTrue(any('IP address' in item['indicator'] for item in result['findings']))
        self.assertIn('verify sender', result['limitations'].lower())
        self.assertIn('Suspicious', result['assessment_status'])

    def test_benign_message_is_not_declared_safe(self):
        result = scan_email('Hi, confirming our meeting tomorrow at 2 PM.')

        self.assertEqual(result['risk_score'], 0)
        self.assertIn('does not prove', result['findings'][0]['indicator'].lower())
        self.assertIn('Inconclusive', result['assessment_status'])

    def test_email_report_contains_evidence_timing_and_input_integrity(self):
        sender = 'analyst@example.org'
        subject = 'Urgent account notice'
        body = 'Verify your password immediately.'
        analysis = scan_email(body, sender, subject)
        input_hash = sha256_email_input(sender, subject, body)
        report = {
            'sender': sender,
            'subject': subject,
            'analysis': analysis,
            'analysis_wall_time_seconds': 0.125,
            'report_generation_time_seconds': 0.005,
            'total_processing_time_seconds': 0.130,
            'sha256_before': input_hash,
            'sha256_after': sha256_email_input(sender, subject, body),
            'integrity_verified': True,
            'integrity_check': (
                'SHA-256 covers the submitted sender, subject, and body; '
                'the original text is not included in the downloadable report.'
            ),
        }

        downloaded_report = json.loads(render_report(report))
        self.assertIn('risk_score', downloaded_report['analysis'])
        self.assertIn('risk_level', downloaded_report['analysis'])
        self.assertTrue(downloaded_report['analysis']['findings'])
        self.assertEqual(downloaded_report['analysis_wall_time_seconds'], 0.125)
        self.assertEqual(downloaded_report['report_generation_time_seconds'], 0.005)
        self.assertEqual(downloaded_report['total_processing_time_seconds'], 0.130)
        self.assertEqual(downloaded_report['sha256_before'], input_hash)
        self.assertEqual(downloaded_report['sha256_after'], input_hash)
        self.assertTrue(downloaded_report['integrity_verified'])
        self.assertEqual(downloaded_report['sender'], '[redacted]')
        self.assertEqual(downloaded_report['subject'], '[redacted]')
        self.assertNotIn(body, json.dumps(downloaded_report))

    def test_malformed_url_does_not_crash_analysis(self):
        result = scan_email('Please review http://[invalid')

        self.assertTrue(any('Malformed URL' in item['indicator'] for item in result['findings']))

    def test_flags_threats_secrecy_qr_and_url_userinfo(self):
        result = scan_email(
            'Final notice: account closes by midnight. Keep this confidential; '
            'scan the QR code or visit https://trusted.example@attacker.test/login'
        )

        indicators = [finding['indicator'] for finding in result['findings']]
        self.assertTrue(any('Threat or deadline' in item for item in indicators))
        self.assertTrue(any('Secrecy' in item for item in indicators))
        self.assertTrue(any('QR-code' in item for item in indicators))
        self.assertTrue(any('embedded credentials' in item for item in indicators))

    def test_extracts_bare_domains_but_not_email_addresses(self):
        result = scan_email(
            'Visit login-example.xyz/path or email help@example.org for assistance.'
        )

        self.assertEqual(result['urls_found'], ['login-example.xyz/path'])
        self.assertTrue(any('Suspicious top-level domain' in item['indicator'] for item in result['findings']))

    def test_extracts_http_url_without_trailing_punctuation(self):
        result = scan_email('Review https://example.com/account.')

        self.assertEqual(result['urls_found'], ['https://example.com/account'])

    def test_flags_punycode_url(self):
        result = scan_email('Review https://xn--e1afmkfd.example/login')

        self.assertTrue(any(
            'punycode/internationalized domain' in finding['indicator']
            for finding in result['findings']
        ))

    def test_free_email_provider_match_uses_exact_sender_domain(self):
        content = 'Urgent: finance needs you to wire transfer the payment now.'

        lookalike = scan_email(content, 'CEO <ceo@notgmail.com>')
        actual_free_provider = scan_email(content, 'CEO <ceo@gmail.com>')

        self.assertFalse(any('Free email provider' in item['indicator'] for item in lookalike['findings']))
        self.assertTrue(any('Free email provider' in item['indicator'] for item in actual_free_provider['findings']))


class UploadSafetyTests(unittest.TestCase):
    def test_pasted_email_text_limit_uses_utf8_bytes(self):
        self.assertEqual(text_input_size_bytes('a' * MIB), MIB)
        self.assertEqual(text_input_size_bytes('a' * (MIB - 1), 'é'), MIB + 1)

    def test_category_limits_match_the_local_acceptance_targets(self):
        examples = {
            'sample.txt': ('text', 1),
            'sample.png': ('image', 10),
            'sample.wav': ('audio', 20),
            'sample.mp4': ('video', 50),
        }
        for filename, (category, limit_mib) in examples.items():
            with self.subTest(filename=filename):
                limit = CATEGORY_LIMITS[category]
                self.assertEqual(limit, limit_mib * MIB)
                self.assertEqual(validate_upload_size(filename, limit), category)
                with self.assertRaisesRegex(UploadValidationError, 'no larger'):
                    validate_upload_size(filename, limit + 1)

    def test_rejects_unsupported_extensions_and_invalid_text(self):
        with self.assertRaisesRegex(UploadValidationError, 'Unsupported file type'):
            validate_upload(b'content', 'message.exe')
        with self.assertRaisesRegex(UploadValidationError, 'UTF-8'):
            validate_upload(b'\xff\xfe', 'message.txt')
        with self.assertRaisesRegex(UploadValidationError, 'binary data'):
            validate_upload(b'hello\x00world', 'message.txt')

    def test_rejects_image_extension_and_content_mismatch(self):
        image_buffer = io.BytesIO()
        Image.new('RGB', (4, 4), color='white').save(image_buffer, format='JPEG')
        with self.assertRaisesRegex(UploadValidationError, 'does not match'):
            validate_upload(image_buffer.getvalue(), 'evidence.png')

    def test_rejects_malformed_image_content(self):
        with self.assertRaisesRegex(UploadValidationError, 'invalid, truncated'):
            validate_upload(b'not an image', 'evidence.png')

    def test_rejects_audio_extension_and_content_mismatch(self):
        with self.assertRaisesRegex(UploadValidationError, 'does not match'):
            validate_upload(b'not a wave file', 'recording.wav')

    def test_rejects_video_extension_and_content_mismatch(self):
        with self.assertRaisesRegex(UploadValidationError, 'does not match'):
            validate_upload(b'not a video file', 'recording.mp4')

    def test_empty_files_are_rejected(self):
        with self.assertRaisesRegex(UploadValidationError, 'empty'):
            validate_upload(b'', 'message.txt')

    def test_reports_redact_identifiers_destinations_and_extracted_text(self):
        report = {
            'filename': 'private-case-name.png',
            'email_sender': 'analyst@example.test',
            'email_subject': 'Confidential account information',
            'email_analysis': {
                'urls_found': ['https://private.example.test/path'],
                'findings': [{'indicator': 'URL contains misleading credentials: https://secret.example.test/'}],
            },
            'qr_payloads': ['https://qr.example.test/token'],
            'ocr': {'text': 'Private OCR content', 'engine': 'test'},
            'video_inspection_error': 'C:\\Users\\Alice\\private\\frame.png',
        }

        safe = privacy_safe_report(report)
        serialized = render_report(report)

        self.assertEqual(safe['filename'], '[uploaded file].png')
        self.assertEqual(safe['email_analysis']['urls_found']['count'], 1)
        self.assertEqual(safe['qr_payloads']['count'], 1)
        self.assertEqual(safe['ocr']['text']['character_count'], len('Private OCR content'))
        self.assertNotIn('private-case-name', serialized)
        self.assertNotIn('analyst@example.test', serialized)
        self.assertNotIn('Confidential account information', serialized)
        self.assertNotIn('private.example.test', serialized)
        self.assertNotIn('secret.example.test', serialized)
        self.assertNotIn('Private OCR content', serialized)
        self.assertNotIn('C:\\\\Users\\\\Alice', serialized)


class LocalRuntimeBoundaryTests(unittest.TestCase):
    def test_only_loopback_streamlit_addresses_are_accepted(self):
        for address in ('127.0.0.1', 'localhost', '::1'):
            with self.subTest(address=address):
                self.assertTrue(is_loopback_bind_address(address))
        for address in ('', None, '0.0.0.0', '192.168.1.10', '::'):
            with self.subTest(address=address):
                self.assertFalse(is_loopback_bind_address(address))


class EvaluationHarnessTests(unittest.TestCase):
    def test_computes_confusion_counts_and_binary_metrics_without_samples(self):
        result = evaluate_rows([
            {'label': 'phishing', 'prediction': 'phishing', 'message': 'private sample'},
            {'label': 'benign', 'prediction': 'benign', 'message': 'another private sample'},
            {'label': 'benign', 'prediction': 'phishing', 'message': 'not emitted'},
            {'label': 'phishing', 'prediction': 'benign', 'message': 'not emitted'},
        ])

        self.assertEqual(result['confusion'], {'tp': 1, 'tn': 1, 'fp': 1, 'fn': 1})
        self.assertEqual(result['metrics'], {
            'precision': 0.5,
            'recall': 0.5,
            'f1': 0.5,
            'accuracy': 0.5,
        })
        self.assertNotIn('private sample', str(result))
        self.assertIn('does not assess calibration', result['limitations'])

    def test_rejects_invalid_labels_and_empty_datasets(self):
        with self.assertRaisesRegex(ValueError, 'must be phishing/benign'):
            evaluate_rows([{'label': 'unknown', 'prediction': 'benign'}])
        with self.assertRaisesRegex(ValueError, 'no records'):
            evaluate_rows([])

    def test_csv_evaluation_requires_dataset_license_and_split_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / 'labels.csv'
            csv_path.write_text('label,prediction\nphishing,phishing\nbenign,benign\n', encoding='utf-8')
            result = evaluate_csv(csv_path, 'controlled-test', 'authorized', 'held-out test')

        self.assertEqual(result['dataset'], 'controlled-test')
        self.assertEqual(result['license'], 'authorized')
        self.assertEqual(result['split'], 'held-out test')
        self.assertEqual(result['records'], 2)


class MediaInspectionTests(unittest.TestCase):
    def test_visual_media_classifier_is_enabled_by_default(self):
        self.assertTrue(should_run_media_classifier_by_default('sample.png'))
        self.assertTrue(should_run_media_classifier_by_default('sample.mp4'))
        for audio_filename in (
            'sample.wav', 'sample.flac', 'sample.ogg', 'sample.aif', 'sample.aiff', 'sample.m4a'
        ):
            with self.subTest(filename=audio_filename):
                self.assertTrue(should_run_media_classifier_by_default(audio_filename))
        self.assertFalse(should_run_media_classifier_by_default('message.eml'))

    def test_benchmark_separates_first_run_from_warm_analysis(self):
        result = analysis_timing_summary([24.0, 4.0, 16.0], 15)

        self.assertEqual(result['first_run_including_initialization_s'], 24.0)
        self.assertEqual(result['warm_avg_analysis_time_s'], 10.0)
        self.assertEqual(result['warm_max_analysis_time_s'], 16.0)
        self.assertFalse(result['warm_runs_within_target'])
        self.assertEqual(result['warm_target_seconds'], 15)

    def test_benchmark_does_not_count_classifier_failures_as_completed(self):
        self.assertEqual(
            model_execution_status({'deepfake_model_error': 'failed'}, True),
            'error',
        )
        self.assertEqual(model_execution_status({}, False), 'disabled')

    def test_image_classifier_result_is_included_in_report(self):
        buffer = io.BytesIO()
        Image.new('RGB', (12, 8), color='white').save(buffer, format='PNG')
        expected = {
            'model': 'test-image-model',
            'model_revision': 'test-revision',
            'fake_probability': 0.9,
            'real_probability': 0.1,
            'model_estimate': 'synthetic-like',
            'limitations': 'test classifier',
            'reported_metrics': {},
        }

        with (
            patch('app.get_image_classifier', return_value=(object(), object(), object())),
            patch('utils.experimental_models.classify_images', return_value=[expected]),
        ):
            report = media_metadata(buffer.getvalue(), 'sample.png', run_models=True)

        self.assertEqual(report['deepfake_classifier_status'], 'completed')
        self.assertEqual(report['experimental_ai_classification'], expected)
        self.assertIn('EXPERIMENTAL MODEL ESTIMATE', report['deepfake_result'])

    def test_image_classifier_download_failure_is_reported(self):
        buffer = io.BytesIO()
        Image.new('RGB', (12, 8), color='white').save(buffer, format='PNG')

        with patch('app.get_image_classifier', side_effect=OSError('model download interrupted')):
            report = media_metadata(buffer.getvalue(), 'sample.png', run_models=True)

        self.assertEqual(report['deepfake_classifier_status'], 'error')
        self.assertEqual(
            report['deepfake_model_error'],
            'Optional local image model could not run; details omitted.',
        )
        self.assertIn('NOT DETERMINED', report['deepfake_result'])

    def test_audio_classifier_result_is_included_in_report(self):
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(b'\x00\x00' * 16000)
        expected = {
            'model': 'test-audio-model',
            'model_revision': 'test-revision',
            'fake_probability': 0.9,
            'real_probability': 0.1,
            'model_estimate': 'synthetic-like',
            'chunks_analyzed': 1,
            'duration_analyzed_seconds': 1.0,
            'duration_omitted_seconds': 0.0,
            'limitations': 'test classifier',
            'reported_metrics': {},
        }

        with (
            patch('app.get_audio_classifier', return_value=(object(), object(), object())),
            patch('utils.experimental_models.classify_audio', return_value=expected),
        ):
            report = media_metadata(buffer.getvalue(), 'sample.wav', 'audio/wav', run_models=True)

        self.assertEqual(report['deepfake_classifier_status'], 'completed')
        self.assertEqual(report['experimental_ai_classification'], expected)
        self.assertIn('EXPERIMENTAL MODEL ESTIMATE', report['deepfake_result'])
        self.assertTrue(report['integrity_verified'])

    def test_m4a_upload_is_decoded_and_audio_estimate_preserves_source_duration(self):
        decoded = io.BytesIO()
        with wave.open(decoded, 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(b'\x00\x00' * (20 * 16000))
        expected = {
            'model': 'test-audio-model',
            'model_revision': 'test-revision',
            'fake_probability': 0.1,
            'real_probability': 0.9,
            'model_estimate': 'human-like',
            'chunks_analyzed': 2,
            'duration_analyzed_seconds': 20.0,
            'duration_omitted_seconds': 0.0,
            'limitations': 'test classifier',
            'reported_metrics': {},
        }
        original = b'\x00\x00\x00\x18ftypM4A \x00\x00\x02\x00unchanged source'

        with (
            patch(
                'utils.experimental_models.decode_m4a_audio',
                return_value=(decoded.getvalue(), 44.16),
            ) as decode,
            patch('app.get_audio_classifier', return_value=(object(), object(), object())),
            patch('utils.experimental_models.classify_audio', return_value=expected),
        ):
            report = media_metadata(original, 'sample.m4a', 'audio/mp4', run_models=True)

        decode.assert_called_once_with(original)
        self.assertEqual(report['media_type'], 'audio')
        self.assertEqual(report['duration_seconds'], 44.16)
        self.assertEqual(report['audio_format'], 'M4A (decoded to WAV for inspection)')
        self.assertEqual(report['experimental_ai_classification']['duration_omitted_seconds'], 24.16)
        self.assertEqual(report['deepfake_classifier_status'], 'completed')
        self.assertTrue(report['integrity_verified'])

    def test_m4a_decode_failure_is_reported(self):
        original = b'\x00\x00\x00\x18ftypM4A \x00\x00\x02\x00not decodable'

        with patch(
            'utils.experimental_models.decode_m4a_audio',
            side_effect=ValueError('unsupported M4A stream'),
        ):
            with self.assertRaisesRegex(UploadValidationError, 'could not be decoded'):
                media_metadata(original, 'sample.m4a', run_models=True)

    def test_audio_classifier_download_failure_is_reported(self):
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(b'\x00\x00' * 16000)

        with patch('app.get_audio_classifier', side_effect=OSError('audio model download interrupted')):
            report = media_metadata(buffer.getvalue(), 'sample.wav', run_models=True)

        self.assertEqual(report['deepfake_classifier_status'], 'error')
        self.assertEqual(
            report['deepfake_model_error'],
            'Optional local audio model could not run; details omitted.',
        )
        self.assertIn('NOT DETERMINED', report['deepfake_result'])

    def test_text_file_runs_email_rules_and_preserves_bytes(self):
        original = b'Subject: Urgent account suspended. Verify your password.'
        report = media_metadata(original, 'message.eml')

        self.assertEqual(report['media_type'], 'text')
        self.assertGreater(report['email_analysis']['risk_score'], 0)
        self.assertEqual(report['sha256_before'], sha256_bytes(original))
        self.assertEqual(report['sha256_before'], report['sha256_after'])
        self.assertTrue(report['integrity_verified'])

    def test_email_file_report_contains_findings_and_recommendations(self):
        report = media_metadata(
            b'Subject: Verify your account\nClick here to confirm your password.',
            'message.txt',
        )

        self.assertIn('findings', report['email_analysis'])
        self.assertTrue(report['email_analysis']['recommendations'])
        self.assertIn('limitations', report['email_analysis'])

    def test_eml_headers_and_body_are_extracted(self):
        original = (
            b'From: Security Team <security@example.test>\r\n'
            b'Subject: Urgent account notice\r\n'
            b'MIME-Version: 1.0\r\n'
            b'Content-Type: text/plain; charset=utf-8\r\n\r\n'
            b'Please verify your password immediately.'
        )

        report = media_metadata(original, 'message.eml')

        self.assertEqual(report['email_sender'], 'Security Team <security@example.test>')
        self.assertEqual(report['email_subject'], 'Urgent account notice')
        self.assertGreater(report['email_analysis']['risk_score'], 0)

    def test_image_metadata_and_hash_are_reported(self):
        buffer = io.BytesIO()
        Image.new('RGB', (12, 8), color='white').save(buffer, format='PNG')
        original = buffer.getvalue()

        report = media_metadata(original, 'sample.png', 'image/png')

        self.assertEqual(report['media_type'], 'image')
        self.assertEqual(report['dimensions'], '12 x 8')
        self.assertEqual(report['mime_type'], 'image/png')
        self.assertTrue(report['integrity_verified'])
        self.assertEqual(report['sha256_before'], report['sha256_after'])

    def test_image_ocr_text_is_checked_for_phishing(self):
        buffer = io.BytesIO()
        Image.new('RGB', (40, 20), color='white').save(buffer, format='PNG')

        class FakeOcrEngine:
            def __call__(self, _image):
                return SimpleNamespace(
                    txts=('Urgent verify your password',),
                    scores=(0.98,),
                    boxes=([[[0, 0], [20, 0], [20, 10], [0, 10]]],),
                    elapse=0.01,
                )

        with patch('app.get_ocr_engine', return_value=FakeOcrEngine()):
            report = media_metadata(buffer.getvalue(), 'message.png', run_ocr=True)

        self.assertIn('Urgent verify your password', report['ocr']['text'])
        self.assertGreater(report['ocr_email_analysis']['risk_score'], 0)
        self.assertTrue(report['integrity_verified'])
        self.assertTrue(any('OCR found suspicious' in item for item in report['recommendations']))

    def test_image_qr_destination_is_screened_without_opening(self):
        import cv2

        qr = cv2.QRCodeEncoder_create().encode('https://192.0.2.1/login')
        qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
        qr = cv2.copyMakeBorder(qr, 32, 32, 32, 32, cv2.BORDER_CONSTANT, value=255)
        buffer = io.BytesIO()
        Image.fromarray(qr).save(buffer, format='PNG')

        report = media_metadata(buffer.getvalue(), 'qr.png')

        self.assertEqual(report['qr_payloads'], ['https://192.0.2.1/login'])
        self.assertTrue(report['qr_email_analysis']['urls_found'])
        self.assertTrue(any(
            'IP address' in finding['indicator']
            for finding in report['qr_email_analysis']['findings']
        ))

    def test_wav_metadata_is_reported(self):
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(8000)
            wav.writeframes(b'\x00\x00' * 8000)

        report = media_metadata(buffer.getvalue(), 'sample.wav', 'audio/wav')

        self.assertEqual(report['media_type'], 'audio')
        self.assertEqual(report['duration_seconds'], 1.0)
        self.assertEqual(report['sample_rate_hz'], 8000)
        self.assertIn('NOT DETERMINED', report['deepfake_result'])
        self.assertIn('does not prove', report['warning'].lower())
        self.assertIn('Inconclusive', report['assessment_status'])

    def test_flac_ogg_and_aiff_metadata_are_supported(self):
        import numpy as np
        import soundfile as sf

        for audio_format, extension in (
            ('FLAC', 'flac'),
            ('OGG', 'ogg'),
            ('AIFF', 'aiff'),
        ):
            with self.subTest(format=audio_format):
                buffer = io.BytesIO()
                sf.write(
                    buffer,
                    np.zeros(8000, dtype=np.float32),
                    8000,
                    format=audio_format,
                )

                report = media_metadata(
                    buffer.getvalue(),
                    f'sample.{extension}',
                )

                self.assertEqual(report['media_type'], 'audio')
                self.assertEqual(report['duration_seconds'], 1.0)
                self.assertTrue(report['integrity_verified'])

    def test_video_metadata_and_sampled_frames_are_reported(self):
        import cv2
        import numpy as np

        with tempfile.NamedTemporaryFile(suffix='.avi', delete=False) as temp_file:
            video_path = temp_file.name
        writer = cv2.VideoWriter(
            video_path,
            cv2.VideoWriter_fourcc(*'MJPG'),
            5,
            (32, 24),
        )
        if not writer.isOpened():
            writer.release()
            os.unlink(video_path)
            self.skipTest('OpenCV video writer is unavailable.')
        try:
            for shade in (0, 80, 160, 240):
                writer.write(np.full((24, 32, 3), shade, dtype=np.uint8))
            writer.release()
            with open(video_path, 'rb') as video_file:
                original = video_file.read()
        finally:
            writer.release()
            os.unlink(video_path)

        report = media_metadata(original, 'sample.avi')

        self.assertEqual(report['media_type'], 'video')
        self.assertEqual(report['frame_count'], 4)
        self.assertEqual(report['sampled_frame_count'], 4)
        self.assertTrue(report['integrity_verified'])

    def test_json_report_is_valid(self):
        report = media_metadata(b'ordinary text', 'message.txt')

        self.assertEqual(json.loads(render_report(report))['filename'], '[uploaded file].txt')

    def test_downloadable_media_report_includes_risk_evidence_timing_and_hashes(self):
        source = b'Urgent: verify your password immediately.'
        report = media_metadata(source, 'message.txt')
        downloaded_report = json.loads(render_report(report))

        self.assertEqual(downloaded_report['email_analysis']['risk_level'], 'Medium Risk - Suspicious indicators present')
        self.assertTrue(downloaded_report['email_analysis']['findings'])
        self.assertEqual(downloaded_report['sha256_before'], sha256_bytes(source))
        self.assertEqual(downloaded_report['sha256_after'], sha256_bytes(source))
        self.assertTrue(downloaded_report['integrity_verified'])
        self.assertGreaterEqual(downloaded_report['analysis_time_seconds'], 0)
        self.assertNotIn(source.decode(), json.dumps(downloaded_report))


class StreamlitUiTests(unittest.TestCase):
    def test_integrity_status_only_shows_the_matching_message(self):
        with patch('app.st.success') as success, patch('app.st.error') as error:
            render_integrity_status(True)
            success.assert_called_once()
            error.assert_not_called()

        with patch('app.st.success') as success, patch('app.st.error') as error:
            render_integrity_status(False)
            error.assert_called_once()
            success.assert_not_called()

    def test_email_screening_renders_a_report(self):
        app_path = Path(__file__).resolve().parents[1] / 'app.py'
        app = AppTest.from_file(str(app_path), default_timeout=30)
        app.query_params['session'] = 'test-session'
        with patch(
            'urllib.request.urlopen',
            side_effect=lambda *args, **kwargs: io.BytesIO(
                b'{"success": true, "username": "test-user"}'
            ),
        ):
            app.run()
            self.assertFalse(app.exception)
            self.assertEqual(
                app.radio(key='dashboard_section').options,
                ['Overview', 'Email', 'Media', 'Files', 'Chat', 'About'],
            )
            self.assertEqual(len(app.file_uploader), 0)
            app.radio(key='dashboard_section').set_value('Email').run()
            self.assertFalse(app.exception)
            checkbox_labels = [checkbox.label for checkbox in app.checkbox]
            self.assertEqual(len(checkbox_labels), 1)
            self.assertTrue(any('email classifier' in label for label in checkbox_labels))
            self.assertTrue(app.checkbox(key='run_email_model').value)
            app.checkbox(key='run_email_model').set_value(False).run()

            app.text_area(key='email_body').set_value(
                'Urgent: verify your password immediately at http://192.0.2.1/login'
            ).run()
            app.button(key='analyze_email').click().run()

            self.assertFalse(app.exception)
            self.assertEqual(app.metric[0].value, '53 / 100')
            self.assertEqual(len(app.download_button), 1)
            self.assertEqual(app.download_button[0].label, 'Download email report (JSON)')
            self.assertEqual(len(app.success), 1)

    def test_media_navigation_exposes_audio_image_and_video_categories(self):
        app_path = Path(__file__).resolve().parents[1] / 'app.py'
        app = AppTest.from_file(str(app_path), default_timeout=30)
        app.query_params['session'] = 'test-session'
        with patch(
            'urllib.request.urlopen',
            side_effect=lambda *args, **kwargs: io.BytesIO(
                b'{"success": true, "username": "test-user"}'
            ),
        ):
            app.run()
            app.radio(key='dashboard_section').set_value('Media').run()
            self.assertFalse(app.exception)
            self.assertEqual(
                app.radio(key='dashboard_media_category').options,
                ['Audios', 'Images', 'Videos'],
            )
            for category, heading in (
                ('Audios', 'Inspect audio'),
                ('Images', 'Inspect image'),
                ('Videos', 'Inspect video'),
            ):
                with self.subTest(category=category):
                    app.radio(key='dashboard_media_category').set_value(category).run()
                    self.assertFalse(app.exception)
                    self.assertTrue(any(heading in item.value for item in app.subheader))
                    self.assertEqual(len(app.file_uploader), 1)

            app.radio(key='dashboard_section').set_value('Files').run()
            self.assertFalse(app.exception)
            self.assertTrue(any('Inspect a file' in item.value for item in app.subheader))
            self.assertEqual(len(app.file_uploader), 1)

    def test_detector_requires_a_portal_session(self):
        app_path = Path(__file__).resolve().parents[1] / 'app.py'
        app = AppTest.from_file(str(app_path), default_timeout=30).run()

        self.assertFalse(app.exception)
        self.assertEqual(len(app.file_uploader), 0)
        self.assertTrue(any(
            'Sign in through the Local-First Threat Analysis app' in item.value
            for item in app.error
        ))


class OptionalModelHelpersTests(unittest.TestCase):
    def test_m4a_decoder_uses_seekable_input_and_limits_decoded_audio(self):
        import sys

        decoded = io.BytesIO()
        with wave.open(decoded, 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            wav.setframerate(16000)
            wav.writeframes(b'\x00\x00' * (20 * 16000))
        original = b'm4a source bytes'
        fake_ffmpeg = ModuleType('imageio_ffmpeg')
        fake_ffmpeg.get_ffmpeg_exe = lambda: 'ffmpeg.exe'
        temporary_path = None

        def fake_run(command, **kwargs):
            nonlocal temporary_path
            temporary_path = command[command.index('-i') + 1]
            self.assertEqual(Path(temporary_path).read_bytes(), original)
            self.assertEqual(command[command.index('-t') + 1], '20')
            self.assertNotIn('input', kwargs)
            return SimpleNamespace(
                returncode=0,
                stdout=decoded.getvalue(),
                stderr=b'Duration: 00:00:44.16',
            )

        with (
            patch.dict(sys.modules, {'imageio_ffmpeg': fake_ffmpeg}),
            patch('utils.experimental_models.subprocess.run', side_effect=fake_run),
        ):
            from utils.experimental_models import decode_m4a_audio

            wav_bytes, duration = decode_m4a_audio(original)

        self.assertEqual(wav_bytes, decoded.getvalue())
        self.assertEqual(duration, 44.16)
        self.assertIsNotNone(temporary_path)
        self.assertFalse(Path(temporary_path).exists())

    def test_audio_model_loader_uses_configured_cache_directory(self):
        import sys

        calls = []

        class FakeFeatureExtractor:
            @staticmethod
            def from_pretrained(model_id, **kwargs):
                calls.append(('processor', model_id, kwargs))
                return object()

        class FakeModel:
            @staticmethod
            def from_pretrained(model_id, **kwargs):
                calls.append(('model', model_id, kwargs))
                return FakeModel()

            def to(self, _device):
                return self

            def eval(self):
                return self

        fake_transformers = ModuleType('transformers')
        fake_transformers.AutoFeatureExtractor = FakeFeatureExtractor
        fake_transformers.AutoModelForAudioClassification = FakeModel
        fake_torch = ModuleType('torch')
        cache_dir = r'D:\detector\hf-cache'

        with (
            patch.dict(sys.modules, {'torch': fake_torch, 'transformers': fake_transformers}),
            patch.dict(os.environ, {'DETECTOR_AUDIO_MODEL_CACHE': cache_dir}),
        ):
            from utils.experimental_models import load_audio_classifier

            processor, model, torch = load_audio_classifier()

        self.assertIsNotNone(processor)
        self.assertIsInstance(model, FakeModel)
        self.assertIs(torch, fake_torch)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call[2]['cache_dir'] == cache_dir for call in calls))

    def test_audio_classifier_resamples_chunks_and_caps_analysis_at_20_seconds(self):
        import numpy as np
        import soundfile as sf

        audio_buffer = io.BytesIO()
        sf.write(audio_buffer, np.zeros(22 * 8000, dtype=np.float32), 8000, format='WAV')
        processed_chunks = []

        class FakeProcessor:
            def __call__(self, audio, *, sampling_rate, return_tensors, padding):
                processed_chunks.append((len(audio), sampling_rate, return_tensors, padding))
                return {'input_values': audio}

        class FakeModel:
            config = SimpleNamespace(id2label={0: 'AIVoice', 1: 'HumanVoice'})

            def __call__(self, **_inputs):
                return SimpleNamespace(logits=[[0.0, 0.0]])

        class FakeTorch:
            @staticmethod
            def inference_mode():
                return nullcontext()

            @staticmethod
            def softmax(_logits, dim):
                self.assertEqual(dim, -1)
                return SimpleNamespace(tolist=lambda: [0.8, 0.2])

        result = classify_audio(
            audio_buffer.getvalue(),
            FakeProcessor(),
            FakeModel(),
            FakeTorch(),
        )

        self.assertEqual([chunk[0] for chunk in processed_chunks], [160000, 160000])
        self.assertTrue(all(chunk[1:] == (16000, 'pt', True) for chunk in processed_chunks))
        self.assertEqual(result['chunks_analyzed'], 2)
        self.assertEqual(result['duration_analyzed_seconds'], 20.0)
        self.assertEqual(result['duration_omitted_seconds'], 2.0)
        self.assertEqual(result['fake_probability'], 0.8)
        self.assertEqual(result['model_estimate'], 'synthetic-like')

    def test_email_classifier_sums_phishing_classes_and_reports_caveats(self):
        class FakeTorch:
            @staticmethod
            def inference_mode():
                return nullcontext()

            @staticmethod
            def softmax(_logits, dim):
                self.assertEqual(dim, -1)
                return SimpleNamespace(tolist=lambda: [0.1, 0.2, 0.3, 0.4])

        class FakeModel:
            def __call__(self, **_inputs):
                return SimpleNamespace(logits=[[0.0, 0.0, 0.0, 0.0]])

        result = classify_email(
            'urgent password reset',
            lambda *_args, **_kwargs: {'input_ids': [1]},
            FakeModel(),
            FakeTorch(),
        )

        self.assertAlmostEqual(result['phishing_probability'], 0.6)
        self.assertEqual(result['model_estimate'], 'phishing-like')
        self.assertIn('not independently reproduced', result['limitations'])

    def test_ocr_adapter_returns_text_scores_and_boxes(self):
        class FakeEngine:
            def __call__(self, _image):
                return SimpleNamespace(
                    txts=('Urgent notice',),
                    scores=(0.95,),
                    boxes=([[[0, 0], [10, 0], [10, 5], [0, 5]]],),
                    elapse=0.02,
                )

        result = extract_text_from_image(Image.new('RGB', (10, 10)), FakeEngine())

        self.assertEqual(result['text'], 'Urgent notice')
        self.assertEqual(result['detections'][0]['confidence'], 0.95)
        self.assertEqual(result['elapsed_seconds'], 0.02)

    def test_qr_payload_is_decoded_without_following_destination(self):
        import cv2
        import numpy as np

        qr = cv2.QRCodeEncoder_create().encode('https://example.com/login')
        qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
        qr = cv2.copyMakeBorder(qr, 32, 32, 32, 32, cv2.BORDER_CONSTANT, value=255)

        payloads = decode_qr_codes(Image.fromarray(qr))

        self.assertEqual(payloads, ['https://example.com/login'])

    def test_qr_scan_skips_single_decode_when_no_multi_code_was_detected(self):
        class FakeDetector:
            single_decode_called = False

            def detectAndDecodeMulti(self, _image):
                return False, (), None, None

            def detectAndDecode(self, _image):
                self.single_decode_called = True
                return '', None, None

        detector = FakeDetector()
        with patch('cv2.QRCodeDetector', return_value=detector):
            payloads = decode_qr_codes(Image.new('RGB', (10, 10)))

        self.assertEqual(payloads, [])
        self.assertFalse(detector.single_decode_called)


if __name__ == '__main__':
    unittest.main()
