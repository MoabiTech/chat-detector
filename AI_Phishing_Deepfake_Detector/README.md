# AI Phishing & Deepfake Detector — Prototype

## Requirements
- Python 3.11 or newer recommended (Pillow 13 security fixes require Python 3.11+)
- pip

## Run the combined app (Windows)

The detector and encrypted chat share one local sign-in page. Start both
services with `start_all.bat`, then use `http://127.0.0.1:5001/` to sign in and
choose **Chat** or **Detector**. The detector opens in a new tab and requires
the active local sign-in session.

Before the first run, install the detector requirements in `.venv`:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The chat launcher creates its own `e2ee_chat\.venv` and installs the chat
requirements automatically when needed. If `py` is not recognized, use
`python` to create the detector virtual environment.

Use `start_detector.bat` or `e2ee_chat\start_server.bat` only to start one
service for development; the combined sign-in flow requires both services.

The app should open in your browser. If it does not, visit the local URL printed in the terminal, usually http://127.0.0.1:8502.

## Local-only input safeguards

The supplied launcher and `.streamlit/config.toml` bind Streamlit to `127.0.0.1`,
limit the upload endpoint to 50 MiB, keep Streamlit's CORS and XSRF protections
enabled, and disable usage-stat collection. The app refuses to start if its
effective Streamlit bind address is not `127.0.0.1`, `localhost`, or `::1`.
Use `start_detector.bat`; do not override the local-only bind setting or expose
the app through a tunnel, reverse proxy, firewall rule, or public listener.

Before analysis, the detector enforces per-category limits of 1 MiB for TXT/EML,
10 MiB for images, 20 MiB for audio, and 50 MiB for video. It validates file
content using UTF-8/EML parsing, image decoding and dimensions, audio parsing,
or media-container signatures and local video decoding. Browser MIME labels are
not trusted. Original upload bytes are analyzed in memory and their before/after
SHA-256 values are compared; processing temporary files are removed by the
existing media helpers. Downloaded JSON and the JSON summary panel redact
filenames, addresses, destinations, QR values, OCR text, and exception details.
The interactive analysis panel can still display values from the user's current
submission; no uploaded sample is written to a project report or log.
Pasted email text, subject, and sender fields are also capped at 1 MiB combined
by their UTF-8 byte length.

The requested target is a maximum of 15 seconds for email/text and media analysis
after optional models are loaded; faster results are acceptable. First-time model
downloads and initialization are reported separately and may take longer than
15 seconds. Report generation has a separate 5-second target. Target-device
measurements on the specified 8 GiB ThinkBook have not been completed. Existing
benchmark data is a separate 11.8 GiB local-machine baseline
with optional OCR and model inference disabled; it does not demonstrate that
the requested targets are met.

To benchmark the OCR and classifier paths, run
`python scripts\benchmark.py --include-ocr --include-models`. This may download
model weights on first use. The results distinguish the first run (including
initialization) from repeat analyses and mark whether the warm runs stayed under
the 15-second target. Without those flags, the benchmark measures the faster
non-OCR, non-classifier path.

## Cybersecurity dashboard

The detector uses a dark, service-style dashboard in `static/cybersecurity.css`. Navigate between **Overview**,
**Email**, **Media**, **Files**, **Chat**, and **About** in the sidebar. Media has separate audio, image, and
video views; Files accepts every supported inspection format. The About view summarizes measured runtimes,
file limits, local models, safe URL/QR handling, SHA-256 integrity checks, encrypted chat, and project notes.
Performance figures are sample measurements, not guarantees or maximum upload limits; model outputs are
experimental and not independently validated.

## Current functionality
- Explainable email phishing rules for urgency, threats/deadlines, credentials, payment requests, MFA manipulation, secrecy, QR-code lures, sender impersonation, and suspicious URL patterns
- Local DistilBERT email classifier enabled by default (can be unchecked for rules-only analysis); weights download on first use
- URL extraction without opening links
- TXT/EML analysis and image/video OCR; extracted text is screened with the same phishing rules
- QR payload extraction from images and sampled video frames; destinations are screened but never opened
- Image technical metadata and perceptual similarity against reference logos in `logos/`
- WAV/FLAC/OGG/AIFF/M4A metadata and local audio deepfake classification, enabled by default for audio uploads
- OpenCV video metadata, OCR from up to eight evenly sampled frames, and optional frame-by-frame image classification
- Before/after SHA-256 integrity checks; original upload bytes are not modified
- Privacy-safe downloadable JSON reports with findings, recommendations, uncertainty, limitations, timing, and SHA-256 integrity checks for uploaded files and pasted email inputs
- Local end-to-end chat demo using browser Web Crypto

## Chat demo

Chat remains a local demonstration, not a production messenger. Its existing
browser-side encryption, fingerprint verification, and limitations are
described in `e2ee_chat\README_E2EE.md`.

## Optional local models and downloads

The app uses CPU inference and downloads model weights to the Hugging Face cache the first time each feature is selected. OCR is enabled by default for images/videos. Experimental email, image/video, and audio classifiers are enabled by default; their checkboxes can be cleared to skip model inference and use the available rules/metadata checks. Email, image/video, and audio model weights need internet access on first use; the image/video classifier downloads about 355 MiB and the audio classifier about 360 MiB. Initial model loading can take longer than analysis, especially on CPU. M4A uploads are decoded locally with FFmpeg to mono 16 kHz PCM, limited to 20 seconds for inspection; the report retains the original upload's hash and full duration. On this Windows setup, the launcher keeps the FFmpeg runtime and audio temporary files on D: (`DETECTOR_FFMPEG_RUNTIME`, `DETECTOR_AUDIO_TEMP_DIR`) and stores the audio model in `D:\detector\hf-cache` with Xet chunks in `D:\detector\hf-cache\xet`; set the corresponding environment variables before launch to override these paths. Hugging Face Xet transfer support is included to improve downloads for large model files.

| Capability | Model/source | Published status |
|---|---|---|
| Email classification | [DistilBERT phishing email classifier](https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.4.1) | Apache-2.0; model card reports 99.58% accuracy, but its label mapping/evaluation are not independently validated here |
| Image and sampled video-frame classification | [SigLIP image classifier](https://huggingface.co/prithivMLmods/deepfake-detector-model-v1) | Apache-2.0; model card labels it experimental and reports 94.44% accuracy on its own evaluation split |
| Audio classification | [Wav2Vec2 audio classifier](https://huggingface.co/Hemgg/Deepfake-audio-detection) | Apache-2.0; model card reports 95.45% accuracy, with evaluation data details not independently verified |
| OCR | [RapidOCR](https://github.com/RapidAI/RapidOCR) ONNX Runtime package | Local OCR; the default model supports Chinese and English |

Model revisions are pinned in `utils/experimental_models.py`. Classifiers run locally; no email or media is sent to an inference API. Initial downloads require internet access and several hundred MiB per transformer model. Each model's report records its exact revision and caveats. Email model scores are kept separate from the rule-based risk score.

## Important limitations

The linked model cards' scores are self-reported and do not prove generalization to this institution, current attacks, different languages, or unseen media generators. This project has not independently validated any model or produced its own labelled test-set precision/recall results. Treat every model output as an experimental estimate, not a forensic verdict.

The image classifier estimates synthetic-like imagery; it is not a general detector of every face swap or image edit. Video classification applies that image model to up to eight sampled frames and does not analyze temporal consistency. Audio classification analyzes up to 20 seconds of WAV/FLAC/OGG/AIFF/M4A audio; M4A decoding requires the bundled FFmpeg dependency. OCR can omit or misread text. Logo similarity compares the uploaded image with reference logos; it does not locate logos embedded inside other images. The `logos/` directory is empty by default, so this signal is inactive until authorized references are supplied. A low score does not prove authenticity; a high score does not prove manipulation. Rules can miss attacks or flag legitimate mail. URL values are extracted but never opened.

For an assignment claim of "validated", evaluate the models against labelled held-out samples representative of the intended use, including false positives/negatives and per-media performance. Do not report the model-card accuracy values as results from this project.

The local chat now has SQLite-backed password accounts, account-bound browser keys, and manual
out-of-band peer fingerprint verification. Users must compare fingerprints independently before
trusting a peer; a compromised server that also changes the served client code remains outside the
protection provided. The prototype has no recovery, forward secrecy, HTTPS, or public deployment
support. Keep it on loopback; do not expose the chat server publicly.

## Labeled-data evaluation

The evaluation helper calculates confusion counts, precision, recall, F1, and
accuracy from a CSV with `label` and `prediction` columns. It requires the
dataset name, license or authorization basis, and split description, and does
not output sample contents. It does not generate predictions or validate the
dataset/model. No labeled-data evaluation results are currently available.
See [EVALUATION.md](./EVALUATION.md) for dataset handling and interpretation.

## Reports, testing, and logo references

- Assignment report drafts are in `reports/`. Replace the group/member placeholders, verify institutional facts with authorized LUCT staff, and check the final page count after formatting for submission.
- The `logos/` directory currently contains no reference images. Add only logos you are authorized to use, then restart the app so the local reference matcher loads them. Until then, the report marks logo matching as inactive.
- Run the detector tests and refresh benchmark measurements from this folder:

```powershell
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
..\.venv\Scripts\python.exe scripts\benchmark.py
```

- Run chat relay and browser-crypto tests from `e2ee_chat`:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
node ..\tests\test_chat_crypto.js
node --check static\app.js
```

- Evaluate authorized labeled data with the standard-library harness in
  [`EVALUATION.md`](EVALUATION.md). No labeled evaluation set is bundled, and
  no project accuracy or calibration metrics are claimed.

The detector is launched with `start_detector.bat`; it is source code plus a Windows launcher, not a packaged standalone executable. See `BUILD_INSTRUCTIONS.md`.
