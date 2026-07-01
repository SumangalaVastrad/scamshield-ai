---
type: scam_type
scam_type: otp_theft
title: OTP, PIN, and CVV theft
aliases: [otp sharing, card verification code, pin disclosure, two factor bypass]
sources:
  - name: "RBI - OTP and PIN Security Advisory"
    url: "https://www.rbi.org.in/commonperson/English/Scripts/Notification.aspx?Id=2108"
    accessed: "2026-10-26" 
last_verified: "2026-10-26"
status: draft
red_flags:
  - "Direct request for OTP, PIN, CVV, or net banking password over phone, SMS, or form"
  - "Caller claims OTP is needed to cancel an unauthorized charge or update security"
  - "Message states 'Do not share this OTP' yet caller insists on reading it out"
urgent_triggers:
  - "shared otp on call"
  - "entered cvv and otp"
  - "disclosed debit card pin"
---

# OTP, PIN, and CVV theft

## Short description
Attackers trick victims into disclosing their One Time Password (OTP), card CVV, or ATM/UPI PIN. They often pose as bank security officers, fraud analysts, or telecom reps claiming the code is necessary to block a fraudulent transaction or reverse a charge.

## How it usually looks
"Dear Customer, an unauthorized charge of Rs 48,500 was initiated on your card. To block this transaction immediately, call our fraud desk or share the 6-digit cancellation OTP sent to your phone."

## Red flags
- Legitimate bank personnel will NEVER ask for your OTP, CVV, or PIN under any circumstances.
- High panic induced by claiming money is already leaking from your account.
- OTP SMS itself clearly states: "Do not share this OTP with anyone, including bank staff".

## What to do now (not yet paid or shared anything)
1. Hang up the call immediately.
2. Never read out or forward an OTP to anyone.
3. Check your transaction alerts and official mobile banking app.
4. Report the call attempt to your bank's fraud detection team.

## What not to do
- Never share OTP, CVV, PIN, or passwords with anyone.
- Never enter your OTP into links sent via WhatsApp or SMS.

## What to do if already clicked, shared, or paid (Urgent)
1. Immediately contact your bank's 24x7 helpline to block the compromised card and freeze net banking.
2. Check for unauthorized debits and report them to the national cybercrime portal/helpline.
3. Change net banking passwords, UPI PINs, and card PINs from a secure device.

## Related types
- [Fake bank KYC update](/scam-types/fake-kyc.md)
- [Fake customer care number](/scam-types/fake-customer-care.md)
