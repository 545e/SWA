# SWA AI — Risk Scoring, CVSS, EPSS & Cisco SIR Governance

## 1. Multi-Dimensional Risk Framework

SWA AI utilizes four distinct, complementary risk assessment frameworks to prioritize findings:

1. **CVSS v3.1 / CVSS v4.0 Base Score**: Standardized technical severity based on intrinsic characteristics of vulnerability (Attack Vector, Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability).
2. **EPSS (Exploit Prediction Scoring System)**: Machine-learning model estimating probability (0.0 to 1.0) that a software vulnerability will be exploited in the wild within the next 30 days.
3. **Cisco Security Impact Rating (SIR)**: Qualitative classification (`Critical`, `High`, `Moderate`, `Low`) reflecting enterprise operational impact.
4. **SWA Organizational Risk Posture Grade**: Aggregate posture grade (`Grade A` to `Grade F`) derived from active vulnerability counts and business criticality weightings.

---

## 2. Qualitative CVSS Thresholds

- **Critical**: CVSS `9.0` – `10.0`
- **High**: CVSS `7.0` – `8.9`
- **Medium**: CVSS `4.0` – `6.9`
- **Low**: CVSS `0.1` – `3.9`
- **None**: CVSS `0.0`

---

## 3. Posture Score Calculation Formula

Platform posture score is calculated dynamically per target workspace:
$$\text{Score} = \max\left(0, 100 - \sum (w_{\text{severity}} \times n)\right)$$

Where base penalties are:
- Critical finding: $-30$ points
- High finding: $-18$ points
- Medium finding: $-8$ points
- Low finding: $-3$ points
- None/Informational: $-1$ point
