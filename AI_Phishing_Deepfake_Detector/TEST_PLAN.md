# Baseline test results (measured 3 November 2026)
# Do not treat model-card metrics or these sample timings as independent model validation.

| ID | Input | Expected check | Actual result | Time (seconds) | Pass/Fail | Notes |
|---|---|---|---|---:|---|---|
| E01 | Test email with urgency + password request | Indicators and score appear (High/Med risk) | Risk score 47 | 0.010446 | Pass | Five benchmark iterations, including JSON report serialization |
| E02 | Benign sample email (legitimate) | Low score, no false high-risk claim; shows 'does not prove safe' disclaimer | Risk score 0 | 0.000708 | Pass | Five benchmark iterations, including JSON report serialization |
| E03 | Email with URL (http/https) | URL extracted but NOT opened by tool | `https://example.com/account` extracted without trailing punctuation | Automated test | Pass | URL parsing is local; no navigation/request is made |
| E04 | Email with IP address URL | IP-based URL flagged | IP URL flagged in email indicator test | Automated test | Pass | Unit test uses a documentation-only IP |
| E05 | Email with punycode domain | Punycode flagged | Punycode URL flagged | Automated test | Pass | |
| M01 | JPG/PNG image | Dimensions, format, size, SHA-256 appear | 1.4679 MiB generated PNG; integrity verified | 0.284331 | Pass | Three benchmark iterations; OCR/classifier inference off; total includes report serialization |
| M02 | WAV audio | Duration, sample rate, channels appear | 1 MiB generated WAV; integrity verified | 0.194687 | Pass | Three benchmark iterations; classifier inference off |
| M05 | M4A audio | Upload decodes locally; classifier runs; source duration and integrity are retained | 44.16 s voice note decoded; model analyzed 20 s and reported 24.16 s omitted | Automated + Streamlit UI test | Pass | Estimate: 5.9% synthetic-like; source SHA-256 unchanged; not a validated accuracy result |
| M03 | Supported video file | Metadata appears when OpenCV reads file | 1.0909 MiB generated AVI; integrity verified | 3.064407 | Pass | Three benchmark iterations; OCR/classifier inference off |
| M04 | Larger PNG image | Capacity and report generation remain successful | 5.6269 MiB PNG; integrity verified | 1.763788 | Pass | Three capacity benchmark iterations; no OCR/classifier |
| I01 | Inspect same file repeatedly | SHA-256 values identical | Before/after SHA-256 matched across every benchmarked media sample | Measured with each media run | Pass | Original bytes are inspected in memory and not rewritten |
| P01 | Representative file each type (<2MiB) | Record analysis time for each | Email, PNG, WAV, and AVI measurements recorded; see below | See below | Pass | Three media iterations and five email iterations |
| P02 | Medium files (1-5MB) | Record times, check stability | 5 MiB WAV processed without error | See `benchmark_results.json` | Pass | |
| P03 | Larger files (up to limit) | Find max successfully processed size | Largest tested: 5.6269 MiB PNG, 5 MiB WAV, 5.5161 MiB AVI | N/A | Partial | These are largest tested samples, not proven maximum limits |
| S01 | JSON report download | Valid JSON, contains all required fields | Automated JSON report test passed | TBD | Pass | |

## Executed Verification (2026-11-03)

- Detector suite: 34 tests passed, including M4A upload/decode/error reporting, default image/video/audio classifier selection, classifier success/failure reporting, audio resampling, 20-second chunking, cache routing, email rules, EML parsing, media metadata, OCR/QR helpers, integrity-status rendering, and Streamlit controls.
- Chat relay suite: 3 tests passed.
- Browser crypto suite: 2 tests passed; JavaScript syntax check passed.
- Detector benchmark refreshed on 2026-11-03; results and environment metadata are in `benchmark_results.json`.
- The benchmark script measured two email samples over five iterations each and generated PNG/WAV/AVI samples over three iterations each. All reported media samples retained their original SHA-256 hashes. The benchmark calls media analysis with OCR and classifier inference disabled; media timings include the default technical checks and QR scanning, and should not be treated as timings for optional OCR/model inference.
- The 588-byte PNG timing has very high run-to-run variability; do not use it as a stable performance estimate. The 1.4679 MiB PNG, 1 MiB WAV, and 1.0909 MiB AVI timings are three-run averages and include JSON serialization. Optional OCR and classifiers were off; results are not service-level guarantees.
- Audio classifier unit tests verify resampling to 16 kHz, chunk-based inference, a 20-second analysis cap, report integration, and visible model-load failures. The model's reported evaluation metrics have not been independently validated by this project.
- M4A upload tests verify the format is enabled by default, FFmpeg decode failures are visible, the classifier analyzes only 20 seconds, the report records omitted duration, and the original source hash remains unchanged.
- M4A end-to-end sample: a 44.16-second voice note decoded and completed real local-model inference; 20 seconds were analyzed, 24.16 seconds were reported as omitted, and the original SHA-256 was unchanged. The output was 5.9% synthetic-like and is only an experimental estimate. Model load plus report took 114.27 seconds on this machine; this is a single sample, not an accuracy or latency benchmark.
- Real-model smoke test: the pinned Wav2Vec2 model loaded from the D: cache and completed classification through `media_metadata` on a generated one-second tone; the report marked classification completed and SHA-256 integrity passed. Cold-load plus report time was 172.63 seconds on this machine; this single synthetic input is not an accuracy or representative latency benchmark.
- Capacity checks successfully processed a 5.6269 MiB PNG, 5 MiB WAV, and 5.5161 MiB AVI through the media-analysis function. These are largest tested samples only; no absolute maximum or Streamlit/browser upload ceiling was established.

## Performance Measurements (Measured samples)

**Test Environment:**
- Machine: Local test machine; hostname omitted
- OS: Windows
- RAM: 11.8 GiB
- CPU: Intel Core i5-1135G7, 8 logical processors
- Python: 3.13.7
- Date Tested: 2026-11-03

**Average Processing Times:**
| Media Type | Avg Analysis (s) | Avg Report JSON (s) | Avg Total (s) | Max Total (s) | Min Total (s) | Runs |
|---|---:|---:|---:|---:|---:|---:|
| Email (text; suspicious sample) | 0.009992 | 0.000444 | 0.010446 | 0.045199 | 0.001503 | 5 |
| Email (text; benign sample) | 0.000497 | 0.000207 | 0.000708 | 0.000813 | 0.000656 | 5 |
| Image (generated PNG; 1.4679 MiB) | 0.282738 | 0.000316 | 0.284331 | 0.302038 | 0.264546 | 3 |
| Audio (generated WAV; 1 MiB) | 0.194181 | 0.000422 | 0.194687 | 0.527376 | 0.028186 | 3 |
| Video (generated AVI; 1.0909 MiB) | 3.058705 | 0.000890 | 3.064407 | 3.334608 | 2.656818 | 3 |

**Observed File Size Capacity (not proven maximum limits):**
| Media Type | Largest Successfully Tested | Notes |
|---|---|---|
| Image | 5.6269 MiB tested successfully | Three-run average total 1.763788 s; largest generated sample, not a proven maximum |
| Audio | 5 MiB tested successfully | Three-run average total 0.136402 s; not a proven maximum |
| Video | 5.5161 MiB tested successfully | Three-run average total 2.705396 s; not a proven maximum |
| Email text | TBD | No maximum-size test run |

## Independent Labelled Classification Validation (Not Yet Performed)

Optional classifiers are integrated, but no project-specific held-out evaluation has been completed. Calculate these metrics only after assembling representative labelled samples:

| Metric | Formula | Result | Notes |
|---|---|---:|---|
| True Positive (TP) | Malicious/synthetic correctly flagged | TBD | |
| False Positive (FP) | Genuine incorrectly flagged | TBD | |
| True Negative (TN) | Genuine correctly not flagged | TBD | |
| False Negative (FN) | Malicious/synthetic missed | TBD | |
| Precision | TP / (TP + FP) × 100% | TBD | |
| Recall (Sensitivity) | TP / (TP + FN) × 100% | TBD | |
| Accuracy | (TP + TN) / (TP + TN + FP + FN) × 100% | TBD | |
| F1-Score | 2×(Precision×Recall)/(Precision+Recall) | TBD | |

*Note: Only calculate metrics with reliable ground truth labels. Experimental model inference is available, but this project has not independently validated the classifiers or established its own held-out evaluation metrics.*
