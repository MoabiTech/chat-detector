# Local evaluation procedure

This prototype currently has no approved, appropriately licensed held-out
dataset, and this work did not generate or claim model accuracy, calibration,
or public-capacity metrics. Existing benchmark observations are sample
measurements, not validated maxima or service guarantees.

## Synthetic email regression cases

`tests/sample_files/email_classification_cases.csv` contains 10 benign and 10
phishing-like email examples authored for this project. The samples are synthetic
and contain no real personal data, credentials, or live links. The detector test
suite runs each row through the rule-based email scanner and checks the expected
class using its existing 35-point suspicious-risk threshold:

```powershell
..\.venv\Scripts\python.exe tests\test_detector.py
```

These are small, hand-authored regression examples, not an independent or
representative held-out dataset. They test configured rule behavior only; they
do not establish model accuracy, generalization, or real-world phishing
detection performance. The optional AI email classifier is not evaluated by
this fixture.

## Labeled-data metrics

The standard-library harness `scripts/evaluate_labeled_data.py` accepts a CSV
with `label` and `prediction` columns. Labels may be `phishing`/`benign` or
`1`/`0`. It prints only dataset-level counts and metrics; it does not print or
store sample rows or message contents. Record the dataset identity, license or
authorization basis, and split when running it:

```powershell
..\.venv\Scripts\python.exe scripts\evaluate_labeled_data.py `
  path\to\authorized-held-out-labels.csv `
  --dataset "approved dataset and version" `
  --license "license or written authorization" `
  --split "held-out test"
```

Keep the input file outside source control and do not include private emails,
personal data, credentials, or unlicensed samples. Review the dataset license,
label semantics, duplicate/near-duplicate leakage, class balance, and
representativeness before interpreting the output. The harness reports TP, TN,
FP, FN, precision, recall, F1, and accuracy for the supplied binary labels; it
does not validate the labels, assess subgroup performance, or establish
forensic validity.

## Calibration and uncertainty

The harness does not assess calibration. Do not describe classifier scores as
calibrated probabilities unless a separate, documented calibration method is
evaluated on held-out data independent of training and threshold selection.
Until that evidence exists, model estimates remain experimental and
uncalibrated; rule-based risk scores are not probabilities.

## Performance and capacity

Measure on the stated Windows 11 / 8 GB target before claiming that any target
is met. The current planning targets are:

| Input/report operation | Target |
|---|---:|
| Text, up to 1 MiB | 5 s |
| Image, up to 10 MiB | 15 s |
| Audio, up to 20 MiB | 30 s |
| Supported video, up to 50 MiB | 60 s |
| Report generation after analysis | 5 s |

Record Python/dependency versions, hardware, sample provenance, cold model-load
time, warm analysis time, report-generation time, run count, and p50/mean/max.
Separate model-enabled measurements from metadata-only runs. The benchmark
script uses generated/representative samples and is not a labeled accuracy or
calibration evaluation. The five-user cloud capacity target remains deferred:
no cloud target is selected and this project must not be publicly exposed.

## Chat and release blockers

The local chat now uses SQLite-backed accounts with scrypt password hashes,
account-bound public keys, browser-persisted non-exportable private keys, and
out-of-band peer fingerprint confirmation. ECDSA signatures bind sender,
recipient, ciphertext, wrapped keys, IVs, and file metadata. Relay and browser
tests cover account authentication, key binding, signing, tamper rejection, and
fingerprint changes. These are regression tests, not a formal cryptographic
review. Password/key recovery, forward secrecy, secure remote transport, rate
limiting, and protection from modified client code are not provided. The server
is loopback-only and must not be exposed publicly.
