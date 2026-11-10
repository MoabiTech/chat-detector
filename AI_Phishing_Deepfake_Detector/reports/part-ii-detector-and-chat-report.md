# Limkokwing University of Technology (LUCT)
## AI-Generated Phishing and Deepfake Media Detector

**Course:** DISS3110 — Information Systems Security  
**Group:** [Enter group number]  
**Members:** [Enter all member names and student numbers]  
**Date:** 3 November 2026

**Contents:** Introduction · System and models · Verification results · Lessons learnt · References

### Introduction

This local prototype screens suspicious email text and inspects text, image, audio, and video files for phishing or synthetic-media indicators. It provides explainable findings and a downloadable JSON report; it is a triage aid, not a forensic verdict. A separate local chat demonstration provides end-to-end encrypted text and file transfer.

### System and models

Email rules check urgency, credential and MFA requests, payments, impersonation, secrecy, QR lures, and suspicious URLs. URLs and QR destinations are extracted and screened but never opened. The local email classifier is enabled by default, and can be unchecked for rules-only analysis. Optional local OCR screens image text and up to eight sampled video frames. The experimental image/video classifier is enabled by default for visual uploads; first use downloads about 355 MiB of model weights. Classifier results remain estimates and are not independently validated by this project.

| Capability | Model / method | Scope and limitation |
|---|---|---|
| Email | DistilBERT `cybersectony/phishing-email-detection-distilbert_v2.4.1` | Enabled by default; up to 512 tokens. Model-card metrics are not this project's evaluation. |
| Image and sampled video frames | SigLIP `prithivMLmods/deepfake-detector-model-v1` | Image-level estimate; video samples at most eight frames and does not analyze temporal consistency. |
| Audio | Wav2Vec2 `Hemgg/Deepfake-audio-detection` | Enabled by default for WAV/FLAC/OGG/AIFF/M4A; M4A is decoded locally and up to 20 seconds are analyzed after first-use model loading. |
| Text extraction | RapidOCR / ONNX Runtime | Optional for images/video; OCR may omit or misread text. |
| Logo comparison | pHash against local `logos/` reference images | Similarity only; compares the uploaded image as a whole, not a logo embedded inside another image. The reference directory is empty, so the signal is inactive until authorized images are added. |

Email risk scoring, OCR/QR findings, classifier estimates, and logo similarity are reported separately. Audio classification is enabled by default for WAV/FLAC/OGG/AIFF/M4A uploads, uses local Wav2Vec2 inference after a first-use model download, and analyzes up to 20 seconds. Video uses frame-level image inference, not a dedicated video model. No model metrics were reproduced on a labelled local test set; do not present model-card accuracy as project accuracy.

### Verification results

Validated on Windows 11, Python 3.13.7, Intel Core i5-1135G7 (8 logical processors), 11.79 GiB RAM, CPU inference. Measurements refreshed on 7 November 2026 are three media runs and five email runs; optional model inference and OCR are disabled. They are sample averages, not performance guarantees and were not measured on the submitted 8 GiB target configuration or in the cloud. Report generation is measured separately as JSON serialization and is included in total time.

| Test input | Average analysis | Average report generation | Average total | Largest successful sample observed |
|---|---:|---:|---:|---:|
| Suspicious email text | 0.006127 s | 0.003137 s | 0.009270 s | Not capacity-tested |
| Benign email text | 0.000471 s | 0.001878 s | 0.002354 s | Not capacity-tested |
| PNG image, 1.4679 MiB | 0.406071 s | 0.004796 s | 0.428021 s | 5.6269 MiB |
| WAV audio, 1 MiB | 0.015747 s | 0.004737 s | 0.039353 s | 5 MiB |
| AVI video, 1.0909 MiB | 1.655972 s | 0.003560 s | 1.663139 s | 5.5161 MiB |

These largest successful samples are not the configured category limits. Upload validation enforces 1 MiB for text, 10 MiB for images, 20 MiB for audio, and 50 MiB for video, along with content checks and image dimension limits. Pasted email fields are capped at 1 MiB combined by UTF-8 byte length. SHA-256 before/after matched on the measured media samples; inspection reads uploaded bytes without rewriting them. **Tests:** 52 detector, 9 chat-relay, and 8 browser-crypto tests pass. Chat coverage includes authentication, access restrictions, peer-key pinning, and an Alice-to-Bob encrypt/decrypt flow.

The 5.6269 MiB PNG, 5 MiB WAV, and 5.5161 MiB AVI capacity samples completed without inspection errors (three-run average total times 1.012684 s, 0.065648 s, and 2.152559 s respectively). These larger-file times are not model-enabled or OCR-enabled. Audio classifier tests use mocked model outputs to verify audio resampling, chunking, and report handling; they are not an independent accuracy or latency evaluation.

An M4A voice note of 44.16 seconds decoded and completed local model inference. The classifier analyzed the first 20 seconds and reported 24.16 seconds omitted; its estimate was 5.9% synthetic-like. The original file hash was unchanged. Model loading plus report generation took 114.27 seconds in this single run. This result is an experimental estimate, not evidence of model accuracy or proof that the voice is genuine.

### Encrypted chat and lessons learnt

The local relay stores scrypt password hashes and account-bound public keys in SQLite. Browser profiles persist non-exportable RSA-OAEP-2048 encryption and ECDSA P-256 signing keys in IndexedDB. Users compare full SHA-256 fingerprints (displayed for their own and peer keys) over an independent trusted channel before sending; changed or unverified keys block text and file sends. Fresh AES-256-GCM keys are wrapped with RSA-OAEP/SHA-256, and ECDSA-SHA-256 signatures bind sender, recipient, ciphertext, wrapped key, IV, and file metadata. Tests demonstrate recipient-only decryption, ciphertext-only relay, authentication rejection, and unauthenticated access controls. The sent-message disclosure shows the encrypted envelope sent to the relay. Traffic metadata remains visible; there is no recovery, forward secrecy, HTTPS, or protection from a compromised server serving modified browser code. Loopback only.

Part I reinforced that risk ownership, evidence, likelihood/impact scoring, and tested controls are needed before residual risk can be accepted. Part II demonstrated the value of independent identity verification, layered detection, safe URL handling, preserving file hashes, measuring performance on real hardware, and documenting limitations. An AI score is not proof: staff must verify high-impact requests through a separately known channel. Future work is to populate the logo reference set with authorized assets, validate models on labelled held-out samples, measure model-enabled latency, and obtain institution-specific risk evidence.

### References (Harvard)

Cybersecurity and Infrastructure Security Agency (CISA) (n.d.) *Avoiding social engineering and phishing attacks*. Available at: https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks (Accessed: 3 November 2026).

CyberSectony (n.d.) *A DistilBERT based phishing email detection model*. Available at: https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.4.1 (Accessed: 3 November 2026).

Hemgg (n.d.) *Deepfake audio recognition*. Available at: https://huggingface.co/Hemgg/Deepfake-audio-detection (Accessed: 3 November 2026).

PrithivMLmods (n.d.) *Deepfake detector model v1*. Available at: https://huggingface.co/prithivMLmods/deepfake-detector-model-v1 (Accessed: 3 November 2026).
