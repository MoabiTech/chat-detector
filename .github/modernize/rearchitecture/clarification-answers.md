---
schema: clarification-answers/v1
status: submitted
generated_at: "2026-11-06T21:26:05.758Z"
scope: [frontend, backend, generic]
questions_file: clarification-questions.json
---

# Rearchitecture Clarification Answers

## 🖥️ Frontend

- **F1** Should the detector keep its current Streamlit interface, or do you require a different frontend framework for the final system?
  - answer: Keep the existing Streamlit interface and harden it
  - source: user
- **F2** Which component approach should the detector use?
  - answer: Use Streamlit's native widgets and the existing cybersecurity CSS
  - source: user
- **F3** The existing interface is available locally at http://127.0.0.1:8501/ and in the project source. Is this the visual baseline, or should the final system follow another design reference?
  - answer: Use the current interface at http://127.0.0.1:8501/ as the baseline
  - source: user
- **F4** Should the cybersecurity styling and supplied asset already in this project remain the design baseline?
  - answer: Keep the current project branding, supplied asset, and cybersecurity CSS
  - source: user
- **F5** What accessibility standard should the interface target?
  - answer: WCAG 2.2 AA
  - source: user
- **F6** Which browsers must the final system support?
  - answer: Current Chrome and Edge on Windows
  - source: user
- **F7** Should the interface support mobile and tablet screens, or is desktop-only sufficient?
  - answer: Responsive desktop, tablet, and mobile
  - source: user
- **F8** Which interface languages are in scope?
  - answer: English only
  - source: user
- **F9** Do you have a preference for frontend state management?
  - answer: Keep Streamlit's existing session-state approach
  - source: user
- **F10** Do you want to keep the current tab navigation, or require another navigation model?
  - answer: Keep the current Streamlit tabs
  - source: user

## ⚙️ Backend

- **B1** Should the current Python Streamlit detector and Flask-SocketIO chat relay remain the backend stack, or is a framework change required?
  - answer: Keep and harden the existing Python Streamlit and Flask-SocketIO applications
  - source: user
- **B2** How should existing detector behavior and chat routes/protocol be handled while hardening the system?
  - answer: Preserve current user-visible behavior and chat protocol; add changes compatibly
  - source: user
- **B3** The current project does not appear to use an application database. Should the system remain database-free, or is persistent storage required?
  - answer: No database or migration; keep analysis local and ephemeral
  - source: user
- **B4** What identity and key-authentication approach is required? This is important because the current chat demo does not authenticate public keys.
  - answer: Internet-accessible service with managed identity, authenticated keys, and production security review
  - source: user
- **B5** What measurable performance, concurrency, and availability targets should acceptance testing meet? If this is coursework on one PC, state the expected hardware and simultaneous users.
  - answer: The system will initially be tested on one Windows 11 computer with lenovo 15 g2 itl thinkbook 11th gen and i5 processor and 8 GB RAM, with testing on the public cloud deployment as well.

The system should support at least one active user on the local computer and a minimum of five simultaneous users during cloud testing.

Proposed performance acceptance targets:

- Email/text analysis: average target of 5 seconds or less.
- Image analysis: average target of 15 seconds or less.
- Audio analysis: average target of 30 seconds or less.
- Video analysis: average target of 60 seconds or less for supported test clips.
- Report generation: target of 5 seconds or less after analysis.
- Initial upload limits: 1 MB for text, 10 MB for images, 20 MB for audio and 50 MB for video.

These are proposed targets, not existing measured results. Actual average processing times, maximum supported file sizes and cloud performance must be measured and reported during testing. The system must show a clear message when a file exceeds its limit or cannot be analysed.
  - source: user

## 📋 General

- **G1** Which outcome defines success for this final project?
  - answer: A reliably runnable local coursework system with repeatable automated tests, measured performance and clearly stated limits; no unverified AI-accuracy claims
  - source: user
- **G2** What should remain explicitly out of scope? Include any features you do not need for your final submission.
  - answer: The project will focus on an operational AI-generated phishing email and deepfake media detection system and an end-to-end encrypted chat application.

The following are outside the project scope:

- Building a new operating system or antivirus product.
- Guaranteeing 100% detection of all phishing attacks or deepfakes.
- Replacing human security analysts or investigations.
- Accessing private company systems or customer databases.
- Collecting real customer passwords, PINs or financial information.
- Claiming that media is authentic or fake without sufficient evidence.
- Developing a commercial banking or mobile money transaction platform.

The system will provide detection results, suspicious indicators, risk levels, confidence or uncertainty information, and recommended security actions. Detection limitations will be clearly explained.
  - source: user
- **G3** Should all current tests remain passing as the project is improved?
  - answer: Must pass; add tests without replacing working coverage
  - source: user
- **G5** Please specify where this system will run (your own Windows computer, a private lab/network, or public cloud), who will use it, any security/privacy requirements, and whether you can provide a labeled email/image/audio/video dataset for measuring false positives and false negatives. You may also state final-submission or demonstration requirements.
  - answer: **Deployment environment**

The system must run on my Windows 11 computer for development, testing and classroom demonstrations. It must also be deployable and accessible through a public cloud hosting service. The local and cloud versions must maintain consistent functionality.

**Security and privacy requirements**

1. Uploaded emails and media files must be analysed without modifying or corrupting the original files.
2. Calculate and compare SHA-256 hashes before and after analysis to verify file integrity.
3. Do not permanently store uploaded private emails, images, audio or videos unless explicitly required and authorised.
4. Protect application secrets, API keys, passwords and encryption keys.
5. Implement secure authentication and access controls for the encrypted chat application.
6. Authenticate and verify public keys to reduce the risk of man-in-the-middle attacks.
7. Use HTTPS for public cloud communication.
8. Validate uploaded file types, file sizes and file contents.
9. Protect the application against malicious uploads, unauthorised access and common web attacks.
10. Do not expose sensitive information in application logs or detection reports.

**AI detection functionality**

The detector must support:
- Phishing email and text analysis.
- Suspicious URL and domain analysis.
- Sender identity and impersonation indicators.
- Copied logo and image similarity checks.
- Deepfake image analysis.
- Deepfake video analysis.
- Synthetic or manipulated audio analysis.

The system must provide an analysis result, risk level, suspicious indicators, processing time and recommended next steps. It must distinguish between a confirmed finding, a suspicious result and an inconclusive result. It must not claim that an unvalidated model can detect all deepfakes.

**Testing and performance evidence**

Testing must include different examples of legitimate and malicious emails, images, audio recordings and videos. Use appropriately licensed public datasets and controlled test samples with known labels. Record true positives, true negatives, false positives and false negatives. Calculate precision, recall, F1-score and accuracy where applicable.

Measure the maximum supported file size, average detection time, report generation time and performance under multiple users. Include screenshots and test results in the final report.

**Dataset requirements**

Use publicly available, appropriately licensed datasets for phishing emails and deepfake image, video and audio samples. Where suitable labelled datasets are unavailable, prepare controlled test samples and document their source and labels. Do not use private customer information.

**End-to-end encrypted chat application**

The chat application must support user registration and authentication, secure key generation and verification, encrypted message transmission, message decryption by the intended recipient, and protection against unauthorised access. Demonstrate that the server cannot read message plaintext. Document the encryption approach and its limitations.

**Final submission and demonstration**

The final project must include working source code, installation instructions, requirements file, test evidence, screenshots, deployment link, user guide and technical documentation. Demonstrate all supported media types, detection reports, file-integrity verification and encrypted messaging. Include lessons learnt, known limitations and recommendations for future improvement.
  - source: user
