# Limkokwing University of Technology (LUCT)
## Information Systems Risk Management

**Course:** DISS3110 — Information Systems Security  
**Assignment:** AI-Generated Phishing and Deepfake Media Detector  
**Group:** [Enter group number]  
**Members:** [Enter all member names and student numbers]  
**Lecturer:** [Confirm lecturer details before submission]  
**Date:** 3 November 2026

> **Evidence boundary:** LUCT is the institution selected in the project plan. No internal policies, asset register, network diagrams, incident records, interviews, or site-audit evidence were provided for this assessment. The asset scenarios below are a proposed university risk baseline, not verified claims about LUCT's current systems or controls. Validate them with authorized institutional staff before presenting them as the institution's actual status quo. Existing controls are recorded as “not verified,” not presumed absent.

## Abstract

This report proposes a repeatable information-systems risk process for a university environment. It identifies representative information assets and threat scenarios, ranks inherent risk using a likelihood-by-impact method, and recommends preventive, detective, and corrective controls. The process follows the risk-assessment principles in NIST SP 800-30 and the governance and continuous-improvement approach of NIST CSF 2.0. Because internal LUCT evidence was unavailable, ratings are initial planning estimates; residual ratings apply only after the listed controls are implemented and tested.

## Contents

1. Scope and method
2. Risk identification
3. Risk assessment
4. Risk control and SecSDLC
5. References

## 1. Scope and method

**Scope:** representative academic, administrative, identity, communications, endpoint, and recovery information systems used by a higher-education institution. Confirm the systems, data owners, suppliers, and campus boundaries with LUCT before adopting the register.

**Process:** establish context and risk criteria; identify assets, threat events, and weaknesses; estimate likelihood and impact; select treatment; assign an accountable owner; test controls; record residual risk and obtain formal acceptance where required. Reassess after significant incidents, system changes, supplier changes, or at least annually.

**Information classification:** identify personal, financial, academic, authentication, and research information; confirm applicable Lesotho privacy and records-retention obligations with the institution's legal or governance office. This report does not determine legal compliance.

## 2. Risk identification

Risk owners below are role-based proposals, not named LUCT appointments. “Existing controls” are unverified pending policy review and staff interviews.

| ID | Representative asset | Threat event and exposure / weakness to validate | Main consequence | Proposed owner | Existing controls |
|---|---|---|---|---|---|
| R1 | Student/staff identity and records | Phishing, credential theft, MFA fatigue, or a deepfake impersonating a senior employee; reporting and independent identity-verification steps may be unclear | Unauthorized disclosure, account takeover, service disruption | IT/Security lead; data owner | Not verified |
| R2 | Finance and payroll systems | Business-email compromise or synthetic voice instructs an employee to change bank details or make an urgent payment; single-person approval or unverified callbacks | Financial loss, payroll diversion, fraud | Finance lead | Not verified |
| R3 | Endpoints, servers, and shared files | Malware/ransomware arrives through an attachment, stolen account, or unpatched device; excessive privileges or weak segmentation may enable spread | Loss of confidentiality and availability; recovery cost | IT operations lead | Not verified |
| R4 | Learning-management and academic systems | Unauthorized access, misconfiguration, or service outage affects course content, grades, examinations, or submissions | Academic disruption; integrity and privacy impact | Academic systems owner | Not verified |
| R5 | Email, collaboration, and institutional domains | Spoofed/lookalike domains or compromised accounts distribute malicious messages; weak sender protections or limited reporting may delay response | Impersonation, fraud, downstream compromise | IT/Security lead; communications lead | Not verified |
| R6 | Backups and recovery copies | Ransomware, deletion, or administrator compromise reaches online backups; restore procedures may be untested | Prolonged outage and unrecoverable records | IT operations lead | Not verified |
| R7 | Supplier/cloud-hosted services | Supplier breach, account compromise, insecure integration, or service failure exposes institutional data | Third-party data exposure or unavailable services | Procurement lead; system owner | Not verified |
| R8 | Staff/student mobile and personal devices | Lost or compromised device exposes sessions, messages, or downloaded records; unmanaged access may lack encryption or revocation | Unauthorized access and privacy incident | IT operations lead; line managers | Not verified |

### Identification evidence to collect

Before the next review, interview IT, finance, academic administration, records/privacy, procurement, and user representatives. Obtain the approved asset inventory, data classifications, identity and access procedures, email-security configuration, incident and near-miss logs, backup/restore test results, supplier register, and business continuity plans. Record evidence source, date, owner, and confidence for each finding; do not include passwords, personal records, or exploitable network details in the class report.

## 3. Risk assessment

### Rating criteria

Score likelihood (L) and impact (I) from 1 to 5. Risk score = L × I. Impact is the highest credible effect on confidentiality, integrity, availability, financial loss, legal obligations, safety, or academic continuity.

| Score | Likelihood guide | Impact guide |
|---:|---|---|
| 1 | Rare; exceptional circumstances | Negligible local inconvenience |
| 2 | Unlikely; limited exposure | Minor, readily recoverable impact |
| 3 | Possible; plausible during the review period | Material disruption or limited sensitive-data exposure |
| 4 | Likely; repeated exposure or weak controls | Major service, financial, privacy, or academic impact |
| 5 | Almost certain or already recurring | Severe, widespread, or difficult-to-recover impact |

| Product L × I | Priority |
|---:|---|
| 1–4 | Low |
| 5–9 | Moderate |
| 10–14 | High |
| 15–25 | Critical |

### Initial inherent ranking

These are **workshop starting estimates**, not measured incident probabilities. Validate likelihood, impact, and the review horizon with the risk owners. Residual scores are illustrative estimates conditional on effective control implementation and successful testing; they are not current LUCT risk ratings.

| Rank | ID | L | I | Inherent score | Priority | Conditional residual L × I |
|---:|---|---:|---:|---:|---|---:|
| 1 | R1 | 4 | 5 | 20 | Critical | 2 × 4 = 8 (Moderate) |
| 1 | R2 | 4 | 5 | 20 | Critical | 2 × 4 = 8 (Moderate) |
| 1 | R3 | 4 | 5 | 20 | Critical | 2 × 4 = 8 (Moderate) |
| 4 | R6 | 3 | 5 | 15 | Critical | 2 × 4 = 8 (Moderate) |
| 5 | R4 | 3 | 4 | 12 | High | 2 × 3 = 6 (Moderate) |
| 5 | R5 | 3 | 4 | 12 | High | 2 × 3 = 6 (Moderate) |
| 5 | R7 | 3 | 4 | 12 | High | 2 × 3 = 6 (Moderate) |
| 8 | R8 | 3 | 3 | 9 | Moderate | 2 × 3 = 6 (Moderate) |

**Decision rule:** Critical and High items require a named owner and documented treatment decision. Do not accept a score solely because it falls below a threshold. The authorized institutional risk owner approves acceptance, records the rationale and expiry/review date, and confirms any applicable legal or contractual constraints. Escalate increases in likelihood, impact, or control failure.

## 4. Risk control and SecSDLC

| ID | Treatment / control type | Proposed actions and verification evidence | Owner | Target residual |
|---|---|---|---|---:|
| R1 | Mitigate — preventive, detective, corrective | Phishing-resistant MFA for privileged/high-risk accounts; least privilege; secure email gateway and domain authentication; user reporting route; alert on risky sign-ins; incident playbook and account-recovery test. Exercise phishing/deepfake verification with a second trusted channel. | IT/Security lead | 8 |
| R2 | Mitigate — preventive, detective | Dual approval for payments and bank-detail changes; callback to a previously recorded number (never the number in the request); separation of duties; transaction alerts and reconciliation; documented exception handling. Test with a safe tabletop scenario. | Finance lead | 8 |
| R3 | Mitigate — preventive, detective, corrective | Supported patching; endpoint protection; remove local admin rights; segment critical systems; restrict macros/scripts; centralized security logs; tested isolation and incident response. Verify patch compliance and alert handling. | IT operations lead | 8 |
| R4 | Mitigate — preventive, corrective | Role-based access; MFA for administrators; change approval; secure backups of grades/course material; availability monitoring; tested restoration and academic continuity plan. | Academic systems owner | 6 |
| R5 | Mitigate — preventive, detective | Protect institutional domains with SPF, DKIM, and DMARC policy; restrict admin access; monitor domain lookalikes and account sign-ins; provide a simple report-phishing workflow and triage SLA. Confirm mail records and run a controlled reporting exercise. | IT/Security lead | 6 |
| R6 | Mitigate — preventive, corrective | Maintain encrypted, access-separated, offline or immutable backups; limit backup administrator roles; define recovery objectives; test restore of representative records and document evidence. | IT operations lead | 8 |
| R7 | Mitigate/transfer — preventive, detective | Maintain supplier and data-flow inventory; perform risk-based due diligence; define security, breach-notification, access, retention, and exit terms; use least-privilege integrations; review supplier incidents and continuity evidence. | Procurement lead; system owner | 6 |
| R8 | Mitigate — preventive, corrective | Require device encryption and screen lock for managed devices; use managed access where available; minimize local downloads; provide prompt lost-device reporting, session revocation, and recovery procedures. | IT operations lead | 6 |

### Governance and SecSDLC checkpoints

1. **Initiation:** sponsor approves scope, classification, risk appetite, owner roles, and review date.
2. **Analysis:** maintain the asset inventory and risk register; verify threats and weaknesses with evidence.
3. **Design:** map each high risk to preventive, detective, and recovery controls; review privacy, supplier, and identity boundaries.
4. **Implementation:** configure controls through change management; train users on independent verification and reporting.
5. **Verification:** test access, mail protections, alerts, payment verification, incident response, and backup restoration; record results and exceptions.
6. **Deployment and operations:** approve residual risk, monitor measures, manage incidents, and update the register after change.

Suggested measures include MFA coverage, privileged accounts reviewed, critical patches overdue, phishing reports triaged within target, payment exceptions independently verified, backup restore tests passed, and high-risk suppliers reviewed. Assign owners and targets after the institution establishes a baseline.

## 5. References (Harvard)

Cybersecurity and Infrastructure Security Agency (CISA) (n.d.) *Avoiding social engineering and phishing attacks*. Available at: https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks (Accessed: 3 November 2026).

National Institute of Standards and Technology (NIST) (2012) *Guide for conducting risk assessments*. NIST Special Publication 800-30 Revision 1. Available at: https://csrc.nist.gov/pubs/sp/800/30/r1/final (Accessed: 3 November 2026).

National Institute of Standards and Technology (NIST) (2024) *The NIST Cybersecurity Framework (CSF) 2.0*. NIST CSWP 29. Available at: https://doi.org/10.6028/NIST.CSWP.29 (Accessed: 3 November 2026).

Limkokwing University of Technology (n.d.) *Lesotho campus website*. Available at: https://limkokwing.net/lesotho/ (Accessed: 3 November 2026). The page could not be retrieved during report preparation; confirm current institutional facts and cite accessible official materials before submission.
