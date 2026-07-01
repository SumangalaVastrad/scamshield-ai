# Evaluation Report: ScamShield AI 4-System Empirical Benchmark

**Date:** 2026-10-27  
**Test Split:** Held-Out Test Set (70 rows, `eval/messages.csv` rows 61–130)  
**Dataset Split:** 60 Tuning rows (not used in this eval) / 70 Held-out rows (34 scams, 36 legitimate alerts, 12 urgent cases).  
**Model Discovered & Evaluated:** `gemini-3.1-flash-lite` (uncached, temperature 0.0).  

---

## 1. Comparative Performance Table

| Metric | System A: Plain LLM | System B: LLM + OKF Notes | System C: Full Agent | System D: Rules Only |
|---|---|---|---|---|
| **Scam F1-Score** | 88.0% | **94.3%** | 86.1% | 49.1% |
| **Scam Recall** | 97.1% (33/34) | 97.1% (33/34) | **100.0% (34/34)** | 41.2% (14/34) |
| **False Alarm Rate** | 22.2% (8/36) | **8.3% (3/36)** | 30.6% (11/36) | 25.0% (9/36) |
| **Urgent Recall** | **100.0% (12/12)** | **100.0% (12/12)** | **100.0% (12/12)** | 25.0% (3/12) |
| **Scam Type Accuracy** | **79.4% (27/34)** | **79.4% (27/34)** | 35.3% (12/34)\* | 47.1% (16/34) |
| **Invented Contacts** | **0** | 1 | 8 | **0** |
| **API Latency (per-call network)** | 4.966s | 3.260s | 3.193s | **0.141s** |
| **Avg Wall Latency / Row** | 4.970s | 3.807s | 9.054s | **0.141s** |
| **Total Wall-Clock Time** | 347.9s (~5.8m) | 266.5s (~4.4m) | 633.7s (~10.5m) | **9.9s** |
| **Avg Tool Calls / Request** | 1.00 | 1.00 | 2.46 | 0.00 |

*\*Note: In System C, the agent outputs free-form descriptive titles ("Digital Arrest Scam", "Remote Access Scam") rather than machine slugs (`impersonation_digital_arrest`, `remote_access_apk`), dropping string-match type accuracy.*

---

## 2. Breakdown Across Hard Held-Out Subsets

### 2.1 Indirect Urgent Cases (IDs 101–105, 5 Scams)
- **System A (Plain LLM):** Scam Recall: 5/5 | Urgent Recall: 5/5
- **System B (LLM + OKF):** Scam Recall: 5/5 | Urgent Recall: 5/5
- **System C (Full Agent):** Scam Recall: 5/5 | Urgent Recall: 5/5
- **System D (Rules Only):** Scam Recall: 1/5 | Urgent Recall: 0/5 (Missed phrases like "they asked me to install an app and I did")

### 2.2 Vague / Ambiguous Prompts (IDs 106–110, 4 Scams, 1 Legit)
- **System A (Plain LLM):** Scam Recall: 4/4 | Urgent Recall: 1/1 | False Alarms: 1/1
- **System B (LLM + OKF):** Scam Recall: 4/4 | Urgent Recall: 1/1 | False Alarms: 1/1
- **System C (Full Agent):** Scam Recall: 4/4 | Urgent Recall: 1/1 | False Alarms: 1/1
- **System D (Rules Only):** Scam Recall: 0/4 | Urgent Recall: 0/1 | False Alarms: 1/1

### 2.3 Hinglish & Kannada (IDs 111–120, 10 Scams)
- **System A (Plain LLM):** Scam Recall: 9/10 | Urgent Recall: 3/3
- **System B (LLM + OKF):** Scam Recall: 9/10 | Urgent Recall: 3/3
- **System C (Full Agent):** Scam Recall: 10/10 | Urgent Recall: 3/3
- **System D (Rules Only):** Scam Recall: 1/10 | Urgent Recall: 0/3

### 2.4 Legitimate Bank / OTP Alerts (36 Legitimate Rows)
- **System A (Plain LLM):** False Alarms: 8/36 (22.2%)
- **System B (LLM + OKF):** False Alarms: 3/36 (8.3%)  <-- OKF notes provide the best false alarm resistance
- **System C (Full Agent):** False Alarms: 11/36 (30.6%)
- **System D (Rules Only):** False Alarms: 9/36 (25.0%)

---

## 3. Representative Failure Cases (5 Per System)

### System A: Plain LLM
1. **ID 72:** IRCTC train cancellation refund. Predicted `upi_refund` instead of `fake_customer_care` due to refund keywords.
2. **ID 75:** Zomato order refund bit.ly link. Predicted `upi_refund` instead of `fake_customer_care`.
3. **ID 76:** Legitimate HDFC Rs 2,450 debit alert. Over-flagged as `SCAM` (`fraud_callback`) because the alert mentions reporting unrecognized debits.
4. **ID 79:** Legitimate ICICI salary credit notice. Over-flagged as `LIKELY SCAM` (`upi_refund`).
5. **ID 91:** Legitimate EPFO monthly contribution alert. Over-flagged as `LIKELY SCAM`.

### System B: LLM + OKF Notes
1. **ID 75:** Zomato customer support refund link. Predicted `upi_refund` instead of `fake_customer_care`.
2. **ID 92:** Legitimate Canara Bank ATM withdrawal notification. Flagged as `SCAM` (`fraud_callback`).
3. **ID 94:** Legitimate Income Tax refund notice. Flagged as `LIKELY SCAM` (`fake_kyc`).
4. **ID 105:** Lucky gift voucher asking for debit card digits and CVV. Classified as `otp_theft` instead of `lottery_prize`.
5. **ID 106:** Vague description ("balance looks different after SMS link"). Classified as `remote_access_apk` instead of `fake_kyc`.

### System C: Full Agent with Tools
1. **ID 61:** CBI digital arrest call. Classified as "Digital Arrest Scam" instead of slug `impersonation_digital_arrest`.
2. **ID 64:** Income Tax penalty notice. Classified as "impersonation_scam" instead of `impersonation_digital_arrest`.
3. **ID 65:** Bank security update app link. Classified as "malware_phishing" instead of `remote_access_apk`.
4. **ID 66:** Credit card reward AnyDesk request. Classified as "Remote Access Scam" instead of `remote_access_apk`.
5. **ID 68:** Active AnyDesk session money debited. Classified as "Remote Access/Screen Sharing Fraud" instead of `remote_access_apk`.

### System D: Rules Only
1. **ID 62:** Customs parcel seizure with narcotics. Classified as `parcel_fee` instead of `impersonation_digital_arrest`.
2. **ID 71:** Fake Swiggy customer care number from Google. Missed entirely (flagged `LOOKS LEGITIMATE`).
3. **ID 72:** IRCTC refund mobile number. Missed entirely (flagged `LOOKS LEGITIMATE`).
4. **ID 74:** Airlines support desk mobile number. Missed entirely (flagged `LOOKS LEGITIMATE`).
5. **ID 101:** "they asked me to install an app and I did". Missed urgent escalation (0/5 urgent recall on indirect cues).

---

## 4. Conclusion & System Selection

- **System D (Rules Only)** is lightning-fast (0.14s) and fully offline, but brittle on novel phrasing, indirect urgency, and Indian languages (49.1% F1).
- **System B (LLM + OKF Notes)** represents the sweet spot: 94.3% F1, 97.1% scam recall, 100% urgent recall, lowest false alarms (8.3%), and 3.26s API latency.
- **System C (Full Agent)** offers maximum adaptability and 100% scam recall, but at the cost of 2.5x tool overhead (9.05s avg wall time) and higher false alarms (30.6%).
