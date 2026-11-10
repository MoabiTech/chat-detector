# AI Phishing & Deepfake Detector - Technical Documentation

## Project Overview
This prototype demonstrates an AI-assisted approach to detecting phishing emails and inspecting media files for deepfake indicators as part of DISS3110 coursework.

## Features Implemented

### 0. User Interface
- Streamlit tabs for pasted email screening and file inspection
- Downloadable JSON reports for both workflows
- TXT/EML uploads are run through email rules and optionally the local classifier

### 1. Email Screening (Rules plus optional classifier)
- Urgency and pressure tactic detection
- Threats, deadlines, secrecy, and process-bypass wording
- Credential/phishing keyword analysis
- MFA manipulation, QR-code, delivery, invoice, and refund lures
- Financial scam indicators (wire transfer, crypto, gift cards)
- URL analysis (IP addresses, punycode/internationalized domains, embedded credentials, suspicious TLDs)
- Suspicious TLD detection (.tk, .ml, .ga, .cf, .gq, .top, .xyz)
- Sender impersonation heuristics (free email + authority claims)
- URL extraction without opening links
- Risk scoring (0-100) with severity levels
- Explainable findings with point values
- Optional local DistilBERT phishing classification; its estimate is separate from the rule score

### 2. Media Inspection
- **Text** (TXT, EML): Email rules applied without opening extracted links
- **Images** (JPG, JPEG, PNG, WEBP, BMP, TIF, TIFF): Format, dimensions, mode, SHA-256
- Optional RapidOCR text extraction from images followed by email rule screening
- QR payload extraction from images and sampled video frames; decoded links are screened but never opened
- Optional experimental image classifier and logo similarity against local reference images
- **Audio** (WAV, FLAC, OGG, AIFF, M4A): Duration, sample rate, channels, format; M4A is decoded locally with FFmpeg
- Experimental synthetic-speech estimate enabled by default for audio uploads; analyzes up to the first 20 seconds
- **Video** (MP4, MOV, AVI, MKV, WEBM): FPS, frame count, duration, dimensions via OpenCV
- Optional OCR and image classification of up to eight evenly sampled video frames
- Perceptual hashing for logo detection (pHash) to identify copied/altered brand logos
- SHA-256 before/after verification of the in-memory upload bytes
- No file modification - original bytes held in memory only

### 3. Reporting & Evidence
- Downloadable JSON reports with timestamps (UTC)
- Analysis time measurement for all operations
- Model status documentation
- Clear disclaimers about limitations

### 4. Model Framework
- Locally loaded pretrained classifiers with pinned Hugging Face revisions
- CPU inference with first-use weight download and subsequent local cache use; image/video/audio inference is enabled by default for those uploads
- Rules, OCR, logo similarity, and model estimates are reported as distinct evidence

## Technical Stack
- **Frontend**: Streamlit 1.66.0
- **Image Processing**: Pillow 12.3.0
- **Video Processing**: OpenCV (opencv-python-headless) 5.0.0.93
- **Perceptual Hashing**: ImageHash
- **ML Framework Ready**: scikit-learn, onnxruntime, numpy, pandas
- **Language**: Python 3.13.7

## Detection Models and Current Status

| Capability | Model | Report status |
|---|---|---|
| Email classification | `cybersectony/phishing-email-detection-distilbert_v2.4.1` | Experimental; model card reports 99.58% accuracy, not independently reproduced |
| Image classification | `prithivMLmods/deepfake-detector-model-v1` | Experimental; model card reports 94.44% on its evaluation split |
| Video classification | Same image classifier applied to up to eight sampled frames | Frame estimates only; no temporal model |
| Audio classification | `Hemgg/Deepfake-audio-detection` | Experimental; WAV, FLAC, OGG, AIFF, and M4A audio is decoded; model card reports 95.45%, evaluation not independently reproduced |
| OCR | RapidOCR | Extracts visible text; output can be incomplete or inaccurate |

The model cards' evaluation figures are third-party claims, not results from this project. The app does not label a file as authentic/fake solely from a score. It reports estimates, model revision, and limitations, and retains rule-based email scoring independently. Formal validation still requires a labelled held-out dataset and analysis of false positives/negatives.

## Performance (Measured)
See benchmark_results.json for actual measurements on this machine.

## Non-Corruption Guarantee
- Files uploaded via Streamlit are read with `.getvalue()` and never rewritten
- SHA-256 is computed both before and after inspection and equality is reported
- Temporary files for video inspection are deleted immediately
- No write operations to source files

## Installation & Usage
`ash
# Activate virtual environment
.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run application
streamlit run app.py
`

## Limitations
- Models are experimental research classifiers, not validated forensic detectors
- Video uses image inference on sparse frames and does not assess temporal artifacts
- Audio analysis is limited to WAV, FLAC, OGG, AIFF, M4A, and the first 20 seconds
- OCR may miss or misread text
- Logo database can be expanded with curated brand logos
- Performance depends on hardware (CPU-only in current environment)

## Future Enhancements
- Evaluate classifier outputs using a labelled, institution-relevant test set
- Expand curated logo references with permission and documented provenance
