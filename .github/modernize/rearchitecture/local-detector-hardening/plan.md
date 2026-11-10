# Modernization Plan: Local Detector Hardening

**Project**: AI Phishing & Deepfake Detector Prototype

## Technical Framework

- **Language**: Python (the repository is a Python project; assessment tooling did
  not recognize it as Java or .NET)
- **Frameworks**: Streamlit detector; Flask-SocketIO chat
- **Build / run**: pip requirements and Windows batch launchers
- **Database**: None selected; scope says analysis remains local and ephemeral
- **Key components**: OpenCV, Pillow, ONNX Runtime/RapidOCR, Transformers, browser
  Web Crypto, Socket.IO
- **Existing verification**: detector and chat tests, browser crypto tests, and a
  benchmark script are present. Repository documentation reports passing tests
  and sample timings; these are not re-run or independently confirmed by this plan.

## Overview

Harden the existing local coursework prototype while retaining its Streamlit
detector, cybersecurity styling, Flask-SocketIO chat behavior and wire protocol.
The result should be repeatably runnable and testable on Windows 11 with the
specified 8 GB target, preserve input files and make limits and uncertainty
visible. Detector and chat remain loopback-only. Public-cloud deployment is
explicitly deferred until identity, verified-key persistence, provider, and
production security decisions are made.

The bounded work is to improve local input/privacy safeguards, preserve and
verify existing user-visible behavior, establish measured test evidence, and
write down unresolved launch gates. It does not provision infrastructure,
introduce a database, choose credentials or identity products, or claim that
the current chat satisfies production identity or key-verification requirements.

## Local Scope and Acceptance Targets

| Area | Acceptance target |
|---|---|
| Detector behavior | Preserve current Streamlit tabs, branding, CSS, and user-visible behavior; support phishing email/text, URLs/domains, sender impersonation, logo similarity, and image, video, and audio analysis. |
| Input integrity/privacy | Validate upload type, size, and content; reject unsupported or oversized inputs clearly. Preserve uploaded bytes and verify matching SHA-256 before/after analysis. Do not retain private uploads; keep sensitive details out of logs and reports. |
| Results | Reports provide result, risk level, indicators, uncertainty, elapsed processing time, and recommended actions. Distinguish confirmed findings, suspicious results, and inconclusive results; do not imply that an AI estimate proves authenticity or manipulation. |
| Limits and local performance | Measure against the specified Windows 11 / 8 GB target. Acceptance goals: text 1 MB / 5 s; image 10 MB / 15 s; audio 20 MB / 30 s; supported video 50 MB / 60 s; report generation within 5 s after analysis. These are targets to verify, not current guarantees. Record cold model-load time separately from warm analysis. |
| Chat | Preserve current Flask-SocketIO protocol and UI style, E2EE behavior, and the existing documented 10 MiB transfer limit unless compatibility tests justify a change. Demonstrate that the relay receives/forwards ciphertext and cannot decrypt message plaintext. Keep the service bound to loopback. |
| Evaluation | Use appropriately licensed public or controlled labeled samples. Record TP, TN, FP, FN, precision, recall, F1, and accuracy where applicable; report the dataset, split, license, method, and limitations. Claim no accuracy value unless measured. Assess calibration on held-out data; where evidence is insufficient, label confidence as uncalibrated/uncertain rather than presenting it as calibrated. |
| Accessibility and UI | Retain Streamlit native controls and existing cybersecurity CSS; verify WCAG 2.2 AA intent, responsive desktop/tablet/mobile presentation, and current Chrome/Edge on Windows. Capture test screenshots. |
| Capacity | Specify and measure future public-cloud behavior for at least five concurrent users only after deployment blockers are resolved. No cloud environment or public listener is created by this plan. |

Existing documentation reports 34 detector tests, 3 chat relay tests, and 2
browser crypto tests passing. It also notes that the largest successful files
tested (5.6269 MiB PNG, 5 MiB WAV, 5.5161 MiB AVI) are observations, not maximum
limits. The stated target sizes above must be tested rather than inferred from
those samples. Existing model-card scores and sample benchmark numbers are not
project validation results.

## Local-Only Impact Summary

| Component | Current state | Planned outcome | Boundary |
|---|---|---|---|
| Streamlit detector | Local multi-modal prototype | Hardened, measured local detector with preserved UI | Loopback/local data only |
| Flask-SocketIO chat | Local E2EE demonstration | Protocol-preserving local demo with relay ciphertext evidence | No public exposure or production identity claim |
| Registration and keys | No persistent verified identity/key mechanism selected | Blocker recorded; implementation gated on an approved design | No silent weakening or invented provider |
| Cloud operation | Not configured by this plan | Deferred acceptance criteria only, including HTTPS and five-user test | No deployment or production security configuration |

## Delivery Boundaries and Gates

- Do not add a database or migration without explicit authorization. Persistent
  registration and verified public keys cannot be claimed complete while storage
  and identity decisions remain open.
- Do not expose either service publicly. No cloud deployment, IaC, container,
  production listener, secrets, or credentials are part of this bounded plan.
- Keep any future cloud release blocked until an identity provider and
  authenticated key-verification/persistence design are selected, HTTPS and
  secret/log/report protections are reviewed, and a production security review
  is completed.
- Keep uploads ephemeral; clean temporary decode artifacts and ensure generated
  reports do not disclose private uploaded content or secrets.
- Treat thresholds as acceptance criteria to measure. Report misses and actual
  observed limits; do not relabel an unachieved target as an established limit.
- Preserve existing test coverage and add tests for the changed behaviors rather
  than replacing working tests.

## Open Questions & Questionnaire

- [ ] How will persistent registration and verified public keys be reconciled
  with the no-database requirement? Select a secure database-free approach or
  explicitly authorize the minimum persistent identity/key records required.
- [ ] Which identity provider and authenticated key-verification mechanism are
  approved for any future internet-accessible service? None is selected.
- [ ] Which public-cloud provider/environment and production security review
  owner are approved? No cloud target is selected; cloud work remains disabled.
- [ ] Which appropriately licensed labeled datasets will be used for held-out
  evaluation and uncertainty calibration? Do not substitute invented metrics.

## Out of Scope

Production/public-cloud deployment, infrastructure generation, selecting or
creating credentials, choosing an identity provider or database, implementing
persistent registration/key verification before the blocking decisions are
approved, making forensic/authenticity guarantees, and claiming unmeasured
accuracy, capacity, or latency.
