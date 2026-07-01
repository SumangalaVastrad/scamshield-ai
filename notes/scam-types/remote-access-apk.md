---
type: scam_type
scam_type: remote_access_apk
title: Malicious APK and remote access
aliases: [anydesk scam, screen share fraud, rustdesk, teamviewer quicksupport, sbi apk update]
sources:
  - name: "National Cybercrime Reporting Portal - Remote Access App Scam"
    url: "https://cybercrime.gov.in"
    accessed: "2026-10-26" 
last_verified: "2026-10-26"
status: draft
red_flags:
  - "Caller asks you to download an app like AnyDesk, RustDesk, or TeamViewer QuickSupport"
  - "Received a direct .apk file link via WhatsApp or SMS to update banking, rewards, or electricity"
  - "App asks for Accessibility and Notification listening permissions to read incoming OTPs"
urgent_triggers:
  - "installed anydesk on caller instruction"
  - "screen sharing was active while logging into bank"
  - "installed apk and screen went blank"
---

# Malicious APK and remote access

## Short description
Scammers trick victims into downloading remote-control apps (like AnyDesk, TeamViewer QuickSupport) or sideloading malicious .apk files disguised as bank updates or reward managers. The malware grants complete access to the victim's phone screen and SMS, intercepting banking credentials and OTPs silently.

## How it usually looks
"Sir, to update your PAN link with your bank account, please download our official customer support app from this link: http://bit.ly/bank-security-support.apk or install QuickSupport from Play Store and tell me the 9-digit code."

## Red flags
- Asks you to install remote access tools or share a screen-mirroring code.
- APK file sent over WhatsApp or third-party web link rather than official app stores.
- Screen turns dark or unresponsive after installing the app while money is being transferred.
- App requests permission to read SMS, draw over other apps, or access accessibility services.

## What to do now (not yet paid or shared anything)
1. Never install remote access tools or sideload APKs upon anyone's recommendation.
2. Refuse to share 9-digit connection codes or session IDs.
3. Uninstall any unknown apps immediately and restart your device in safe mode if needed.

## What not to do
- Never open your banking apps or enter UPI PINs while screen sharing is active.
- Never grant Accessibility or Notification permissions to unfamiliar applications.

## What to do if already clicked, shared, or paid (Urgent)
1. Turn off Wi-Fi and Mobile Data immediately, or turn on Airplane mode to break the attacker's remote connection.
2. Call your bank immediately from another phone to freeze all accounts, net banking, and cards.
3. Uninstall the malicious application, or perform a factory reset of the phone.
4. Report the incident to the cybercrime helpline.

## Related types
- [OTP and credential theft](/scam-types/otp-theft.md)
- [Fake bank KYC update](/scam-types/fake-kyc.md)
