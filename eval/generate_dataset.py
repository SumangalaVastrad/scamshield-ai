"""Script to generate the 100 synthetic evaluation messages dataset for eval/messages.csv."""

import csv
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
eval_dir = repo_root / "eval"
eval_dir.mkdir(parents=True, exist_ok=True)
csv_path = eval_dir / "messages.csv"

# 100 labeled evaluation messages
MESSAGES = [
    # --- SCAM TYPE 1: Fake KYC (1-7) ---
    (1, "Dear SBI User, your KYC has expired. Your account will be blocked within 24 hours. Update immediately at http://bit.ly/sbi-kyc-verify", "scam", False, "fake_kyc", "en", "Synthetic SBI KYC SMS with shortened link", ""),
    (2, "HDFC Alert: Your NetBanking is suspended due to pending PAN card link. Click http://cutt.ly/hdfc-pan to reactivate now.", "scam", False, "fake_kyc", "en", "Synthetic HDFC PAN alert", ""),
    (3, "प्रिय ग्राहक, आपका बैंक खाता आज ब्लॉक हो जाएगा। तुरंत पैन कार्ड अपडेट करें: http://tinyurl.com/bank-kyc-update", "scam", False, "fake_kyc", "hi", "Synthetic Hindi KYC threat SMS", ""),
    (4, "ICICI Bank: Important notice! Your debit card is deactivated due to missing Aadhaar KYC. Update here: http://bit.ly/icici-aadhaar", "scam", False, "fake_kyc", "en", "Synthetic ICICI Aadhaar update scam", ""),
    (5, "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ಕೆವೈಸಿ ಮುಕ್ತಾಯಗೊಂಡಿದೆ. 24 ಗಂಟೆಗಳಲ್ಲಿ ಅಮಾನತುಗೊಳ್ಳುತ್ತದೆ: http://bit.ly/kannada-kyc", "scam", False, "fake_kyc", "kn", "Synthetic Kannada KYC alert", ""),
    (6, "Your Kotak account requires urgent re-KYC. Fill the form at http://kotak-kyc-verify.xyz or visit branch before 5 PM.", "scam", False, "fake_kyc", "en", "Synthetic Kotak lookalike TLD", ""),
    (7, "Dear customer, your PNB account is blocked today. I panicked and already clicked the link and entered my card details.", "scam", True, "fake_kyc", "en", "Synthetic KYC scam with urgent action taken", "entered card details"),

    # --- SCAM TYPE 2: Parcel / Courier Fee (8-14) ---
    (8, "India Post: Your package IND98421 cannot be delivered due to incomplete street address. Pay Rs. 25 redelivery fee at http://cutt.ly/post-fee", "scam", False, "parcel_fee", "en", "Synthetic India Post redelivery fee scam", ""),
    (9, "BlueDart: Your courier is stuck at customs. Clear handling charge of Rs 49 within 12 hours: http://bit.ly/bluedart-clearance", "scam", False, "parcel_fee", "en", "Synthetic BlueDart customs fee scam", ""),
    (10, "DTDC Alert: Address missing for shipment #8932. Please confirm address and pay Rs 15 update fee at http://dtdc-tracking.top", "scam", False, "parcel_fee", "en", "Synthetic DTDC lookalike link", ""),
    (11, "India Post parcel IND2301 awaiting redelivery. I called the number and paid Rs 25 via UPI already.", "scam", True, "parcel_fee", "en", "Synthetic parcel fee with urgent payment", "already paid"),
    (12, "Delhivery Courier: Delivery failed. Re-schedule delivery and pay Rs 30 at http://bit.ly/delhivery-redeliver", "scam", False, "parcel_fee", "en", "Synthetic Delhivery failed delivery SMS", ""),
    (13, "ನಿಮ್ಮ ಇಂಡಿಯಾ ಪೋಸ್ಟ್ ಪಾರ್ಸೆಲ್ ವಿಳಾಸ ತಪ್ಪಾಗಿದೆ. ರೂ 25 ಶುಲ್ಕ ಪಾವತಿಸಿ: http://bit.ly/post-kn", "scam", False, "parcel_fee", "kn", "Synthetic Kannada India Post SMS", ""),
    (14, "FedEx: Your international package is held. Pay customs clearance of Rs 1,450 to avoid return: http://bit.ly/fedex-clear", "scam", False, "parcel_fee", "en", "Synthetic FedEx customs fee scam", ""),

    # --- SCAM TYPE 3: UPI Refund / Collect Request (15-21) ---
    (15, "Sir I am sending Rs 10,000 for your OLX refrigerator. Open your Google Pay, accept collect request and enter your UPI PIN to receive money.", "scam", False, "upi_refund", "en", "Synthetic OLX UPI collect trick", ""),
    (16, "PhonePe Cashback: You won Rs 1,999 cashback! Click http://bit.ly/phonepe-reward and enter your UPI PIN to claim money to bank.", "scam", False, "upi_refund", "en", "Synthetic cashback UPI PIN scam", ""),
    (17, "Paytm Refund: Rs 750 refund initiated for order #9821. Approve request and enter PIN on your Paytm app immediately.", "scam", False, "upi_refund", "en", "Synthetic Paytm refund collect request", ""),
    (18, "I received a collect request on Google Pay for Rs 4000. The buyer told me to enter PIN to receive payment, and I already gave my PIN and money was debited!", "scam", True, "upi_refund", "en", "Synthetic UPI collect scam with debit", "entered PIN, money debited"),
    (19, "Payment received from merchant store. To reverse double deduction, scan this QR code and approve transfer in BHIM.", "scam", False, "upi_refund", "en", "Synthetic QR code reversal scam", ""),
    (20, "Amazon Pay: Your cashback of Rs 2,500 is pending. Send request to claim-reward@okaxis to receive balance.", "scam", False, "upi_refund", "en", "Synthetic Amazon Pay reward trick", ""),
    (21, "Sir send Rs 1 to test my UPI ID rahul.sharma@paytm, then I will send Rs 15,000 for your camera.", "scam", False, "upi_refund", "en", "Synthetic UPI test transfer bait", ""),

    # --- SCAM TYPE 4: Fake Job Offer / Task Scam (22-28) ---
    (22, "Part-time job offer: Earn Rs 3,000 to Rs 8,000 daily from home! Just like YouTube videos. Contact HR on Telegram @WorkDailyTasks", "scam", False, "fake_job", "en", "Synthetic YouTube task job scam", ""),
    (23, "Amazon HR: Work from home hotel review tasks. Earn Rs 500 per review. Join our Telegram group http://t.me/AmazonReviewHR", "scam", False, "fake_job", "en", "Synthetic hotel review task scam", ""),
    (24, "घर बैठे रोजाना 2000 से 5000 रुपये कमाएं। केवल वीडियो लाइक करें। व्हाट्सएप पर संपर्क करें +91 9876543210", "scam", False, "fake_job", "hi", "Synthetic Hindi work from home job SMS", ""),
    (25, "I joined a Telegram task job. They paid Rs 150 first, but then I transferred Rs 15,000 for VIP task and now they are asking Rs 50,000 to withdraw!", "scam", True, "fake_job", "en", "Synthetic prepaid task trap with urgent money sent", "already transferred Rs 15,000"),
    (26, "Google Maps rating job: Rate 5 restaurants daily and get Rs 1,500 credited to your UPI. Register at http://bit.ly/maps-job-task", "scam", False, "fake_job", "en", "Synthetic Google Maps rating scam", ""),
    (27, "Data entry work from home: Earn Rs 25,000/month. No experience needed. Pay refundable security deposit of Rs 999 to start.", "scam", False, "fake_job", "en", "Synthetic data entry deposit scam", ""),
    (28, "Instagram influencer task: Like posts and earn instant cash. Deposit Rs 2,000 to unlock higher commission tier.", "scam", False, "fake_job", "en", "Synthetic influencer task scam", ""),

    # --- SCAM TYPE 5: Investment & Crypto Scam (29-35) ---
    (29, "Exclusive Institutional Trading Group: 100% guaranteed 30% weekly profit on upper-circuit stock calls. Join SEBI Registered VIP group: http://bit.ly/stock-vip", "scam", False, "investment_scam", "en", "Synthetic stock tip group scam", ""),
    (30, "Double your crypto in 7 days! AI automated arbitrage bot gives 15% daily return. Deposit USDT to wallet address.", "scam", False, "investment_scam", "en", "Synthetic crypto high yield scam", ""),
    (31, "Pre-IPO allotment: Buy NSE unlisted shares at 50% discount before public listing. Transfer funds to institutional escrow account.", "scam", False, "investment_scam", "en", "Synthetic fake IPO allocation scam", ""),
    (32, "I invested Rs 1,50,000 in a Telegram stock trading platform. The dashboard shows Rs 5 Lakhs but they are demanding 20% tax before releasing funds. I already transferred my savings!", "scam", True, "investment_scam", "en", "Synthetic investment scam with major money sent", "already transferred savings"),
    (33, "Forex trading signals: Join Master Trader WhatsApp group. 99% accuracy guaranteed. Minimum deposit Rs 10,000.", "scam", False, "investment_scam", "en", "Synthetic forex group scam", ""),
    (34, "Gold trading scheme: Invest Rs 5,000 and get Rs 12,000 in 10 days guaranteed under government backed fund.", "scam", False, "investment_scam", "en", "Synthetic gold doubling scheme", ""),
    (35, "शेयर मार्केट में पक्का मुनाफा: हमारे वीआईपी ग्रुप में शामिल हों और हर महीने 50% रिटर्न पाएं।", "scam", False, "investment_scam", "hi", "Synthetic Hindi stock trading group", ""),

    # --- SCAM TYPE 6: Fake Loan App (36-41) ---
    (36, "Instant Cash Loan: Rs 50,000 approved in 5 minutes! No CIBIL required. Install our quick loan APK: http://bit.ly/quick-cash-loan", "scam", False, "fake_loan_app", "en", "Synthetic 7-day loan app SMS", ""),
    (37, "Fast Rupee: Your personal loan of Rs 1,00,000 is ready. Download app from http://loan-quick.xyz to disburse immediately.", "scam", False, "fake_loan_app", "en", "Synthetic loan app lookalike link", ""),
    (38, "I installed a loan app yesterday and got Rs 3,000. Now they are threatening me and sending morphed photos to all my contacts demanding Rs 10,000!", "scam", True, "fake_loan_app", "en", "Synthetic loan app harassment urgent", "installed app, threatening me"),
    (39, "Low interest personal loan at 2% annual rate. Pre-approved for your mobile number. Click http://bit.ly/instant-credit-now", "scam", False, "fake_loan_app", "en", "Synthetic unrealistically low interest loan", ""),
    (40, "ತುರ್ತು ಸಾಲ ಬೇಕೇ? 10 ನಿಮಿಷಗಳಲ್ಲಿ 25,000 ರೂ ಪಡೆಯಿರಿ. ಯಾವುದೇ ದಾಖಲೆಗಳಿಲ್ಲ: http://bit.ly/kannada-loan", "scam", False, "fake_loan_app", "kn", "Synthetic Kannada loan app SMS", ""),
    (41, "Emergency loan alert: Processing fee of Rs 500 required to release your sanctioned Rs 75,000 loan.", "scam", False, "fake_loan_app", "en", "Synthetic loan advance processing fee bait", ""),

    # --- SCAM TYPE 7: OTP / Credential Theft (42-47) ---
    (42, "Security Alert: An unauthorized transaction of Rs 24,999 was detected on your card. Call 9876543210 immediately to block and share cancellation OTP.", "scam", False, "otp_theft", "en", "Synthetic fake fraud alert demanding OTP", ""),
    (43, "Dear Customer, someone attempted to login to your NetBanking from New Delhi. Share the verification OTP to secure your account.", "scam", False, "otp_theft", "en", "Synthetic fake login alert seeking OTP", ""),
    (44, "Bank officer on call told me my card is blocked. I panicked and I shared OTP and CVV on call with him 10 minutes ago!", "scam", True, "otp_theft", "en", "Synthetic OTP disclosure urgent", "shared OTP and CVV"),
    (45, "Rewards points expiring: Redeem Rs 8,450 worth of points into your bank. Enter debit card number, CVV and OTP at http://bit.ly/reward-redeem", "scam", False, "otp_theft", "en", "Synthetic reward points credential theft", ""),
    (46, "Aadhaar verification: To link Aadhaar with bank, please tell me the 6-digit OTP you just received from UIDAI.", "scam", False, "otp_theft", "en", "Synthetic Aadhaar OTP phishing call", ""),
    (47, "Dear user, share the 4 digit PIN sent to your phone to activate 5G services on your Airtel SIM card.", "scam", False, "otp_theft", "en", "Synthetic SIM 5G PIN scam", ""),

    # --- SCAM TYPE 8: Utility Disconnection (48-53) ---
    (48, "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM because previous month bill was not updated. Call electricity officer at 9876543210 immediately.", "scam", False, "utility_disconnection", "en", "Synthetic electricity disconnection SMS", ""),
    (49, "BESCOM Notice: Power supply will be cut today at 8:00 PM due to unpaid electricity bill. Contact BESCOM supervisor on 9123456789.", "scam", False, "utility_disconnection", "en", "Synthetic BESCOM electricity notice", ""),
    (50, "Gas Connection Warning: Your PNG gas line will be disconnected tonight at 10 PM. Call gas executive at 09876543210 to avoid disconnection.", "scam", False, "utility_disconnection", "en", "Synthetic gas disconnection threat", ""),
    (51, "I received an electricity disconnection SMS and called the number. The man made me download an app and Rs 12,000 was debited from my account!", "scam", True, "utility_disconnection", "en", "Synthetic electricity bill scam debit urgent", "money was debited"),
    (52, "प्रिय उपभोक्ता, आपकी बिजली आज रात 9:30 बजे काट दी जाएगी। तुरंत अधिकारी से 9876543210 पर संपर्क करें।", "scam", False, "utility_disconnection", "hi", "Synthetic Hindi electricity disconnection SMS", ""),
    (53, "Water Board Warning: Water connection deactivation scheduled for tomorrow morning. Pay pending bill of Rs 350 at http://bit.ly/water-bill-pay", "scam", False, "utility_disconnection", "en", "Synthetic water bill disconnection threat", ""),

    # --- SCAM TYPE 9: Lottery & Prize Scam (54-58) ---
    (54, "Congratulations! Your mobile number won Rs 25,00,000 in KBC Lucky Draw 2026. Contact Manager Rana Pratap on WhatsApp at +91-9876543210 to claim prize.", "scam", False, "lottery_prize", "en", "Synthetic KBC lottery WhatsApp scam", ""),
    (55, "Tata Motors Promo: You have won a new Tata Safari car in Diwali lucky contest. Pay Rs 14,500 RTO registration fee to claim your car.", "scam", False, "lottery_prize", "en", "Synthetic car lottery registration fee scam", ""),
    (56, "I received a message saying I won Rs 25 Lakhs in lottery. I already sent Rs 10,000 for government tax fee and now they are asking for Rs 25,000 more!", "scam", True, "lottery_prize", "en", "Synthetic lottery scam urgent money sent", "already sent Rs 10,000"),
    (57, "iPhone 16 Lucky Winner: Your email was selected for free Apple iPhone. Pay delivery charges of Rs 499 at http://bit.ly/iphone-claim", "scam", False, "lottery_prize", "en", "Synthetic free phone prize delivery bait", ""),
    (58, "बधाई हो! आपने कौन बनेगा करोड़पति में 25 लाख जीते हैं। लॉटरी का पैसा लेने के लिए मैनेजर से संपर्क करें।", "scam", False, "lottery_prize", "hi", "Synthetic Hindi lottery prize SMS", ""),

    # --- SCAM TYPE 10: Impersonation & Digital Arrest (59-64) ---
    (59, "This is Inspector Sharma from Mumbai Cyber Police. A parcel containing 5 fake passports and MDMA drugs was sent in your name. You are under digital arrest on this Skype video call.", "scam", False, "impersonation_digital_arrest", "en", "Synthetic digital arrest police call", ""),
    (60, "TRAI & DoT Warning: Your mobile number will be disconnected in 2 hours as it is linked to illegal money laundering cases registered in Delhi CBI.", "scam", False, "impersonation_digital_arrest", "en", "Synthetic TRAI SIM disconnection scam", ""),
    (61, "A man claiming to be CBI Officer is currently on video call with me threatening digital arrest and demanding I transfer all my money to RBI verification account right now!", "scam", True, "impersonation_digital_arrest", "en", "Synthetic digital arrest active call urgent", "currently on video call, threatening digital arrest"),
    (62, "Customs Office Mumbai: Parcel sent to USA in your Aadhaar name seized with narcotics. Warrant issued. Call Customs Officer immediately at 9876543210.", "scam", False, "impersonation_digital_arrest", "en", "Synthetic customs narcotics parcel call", ""),
    (63, "CBI Special Cell: Non-bailable warrant issued against your PAN. Transfer Rs 50,000 security deposit to court escrow account to avoid physical arrest.", "scam", False, "impersonation_digital_arrest", "en", "Synthetic CBI warrant extortion demand", ""),
    (64, "Income Tax Department Notice: Tax evasion case detected. Pay penalty of Rs 15,000 immediately to avoid arrest: http://bit.ly/tax-penalty-pay", "scam", False, "impersonation_digital_arrest", "en", "Synthetic Income Tax arrest threat", ""),

    # --- SCAM TYPE 11: Remote Access & Malicious APK (65-70) ---
    (65, "Bank Support: To update your mobile banking security, please download our official support app: http://bit.ly/sbi-security-patch.apk and install it.", "scam", False, "remote_access_apk", "en", "Synthetic banking APK download scam", ""),
    (66, "Sir to fix your credit card reward issue, install AnyDesk app from Play Store and tell me the 9-digit connection code.", "scam", False, "remote_access_apk", "en", "Synthetic AnyDesk remote control request", ""),
    (67, "Electricity Board Support: Install QuickSupport app so our technician can verify your meter reading remotely and clear pending bill.", "scam", False, "remote_access_apk", "en", "Synthetic TeamViewer QuickSupport meter scam", ""),
    (68, "A caller asked me to install AnyDesk for bank refund. Screen sharing was active and I already saw Rs 45,000 debited from my SBI account!", "scam", True, "remote_access_apk", "en", "Synthetic AnyDesk debit urgent", "installed AnyDesk, Rs 45,000 debited"),
    (69, "Update your WhatsApp to WhatsApp Pink with exclusive features. Download APK here: http://bit.ly/whatsapp-pink-app", "scam", False, "remote_access_apk", "en", "Synthetic WhatsApp Pink trojan link", ""),
    (70, "Install RustDesk remote tool to resolve your EPFO pension processing immediately.", "scam", False, "remote_access_apk", "en", "Synthetic RustDesk remote access trick", ""),

    # --- SCAM TYPE 12: Fake Customer Care (71-75) ---
    (71, "I searched Google for Swiggy refund customer care and called the mobile number 9876543210. The person asked me to pay Rs 5 registration fee via link.", "scam", False, "fake_customer_care", "en", "Synthetic Google search fake customer care", ""),
    (72, "IRCTC Refund Helpline: Call 9123456789 for train cancellation refund. Executive will process refund to your Google Pay.", "scam", False, "fake_customer_care", "en", "Synthetic fake IRCTC helpline", ""),
    (73, "I called a customer care number found on Google for flight refund. They asked for my debit card details and I entered my card number and CVV!", "scam", True, "fake_customer_care", "en", "Synthetic fake helpline card details shared urgent", "entered card number and CVV"),
    (74, "Airlines support desk: Dial 9876543210 for immediate ticket reschedule and refund without cancellation charges.", "scam", False, "fake_customer_care", "en", "Synthetic fake airline support desk", ""),
    (75, "Zomato customer support: To refund your wrong order, click this UPI refund link: http://bit.ly/zomato-refund-now", "scam", False, "fake_customer_care", "en", "Synthetic fake food delivery refund link", ""),

    # --- LEGITIMATE MESSAGES (76-100: 25 rows) ---
    (76, "Dear Customer, Rs. 2,450.00 debited from your HDFC Bank A/C XX4921 on 26-Oct-2026. Avail Bal: Rs 34,210.00. If not done by you, SMS BLOCK to 5676712. Do not share OTP with anyone.", "legit", False, "", "en", "Synthetic genuine bank transaction debit alert", ""),
    (77, "483921 is your secret OTP for login to SBI NetBanking. Valid for 10 minutes. Do not share this OTP with anyone, including bank staff. State Bank never asks for OTP.", "legit", False, "", "en", "Synthetic genuine bank login OTP notice", ""),
    (78, "Your Amazon order #402-9831201 has been dispatched via BlueDart tracking #982143. Expected delivery: Tomorrow by 8 PM.", "legit", False, "", "en", "Synthetic genuine e-commerce shipping notice", ""),
    (79, "ICICI Bank: Rs 50,000 credited to account XX1209 via NEFT from TATA CONSULTANCY SERVICES on 25-Oct-2026. Net balance: Rs 82,400.", "legit", False, "", "en", "Synthetic genuine salary credit notice", ""),
    (80, "Dear Customer, your electricity bill of Rs 1,420 for consumer #893210 is due on 05-Nov-2026. Pay safely through BESCOM official app or website.", "legit", False, "", "en", "Synthetic genuine utility bill reminder without links", ""),
    (81, "894210 is your OTP for purchase of Rs 850 at Swiggy on Axis Bank Credit Card XX9981. Do not share OTP with anyone.", "legit", False, "", "en", "Synthetic genuine merchant OTP alert", ""),
    (82, "India Post: Consignment IND98234 has been delivered at Indiranagar PO to consignee on 26-Oct-2026.", "legit", False, "", "en", "Synthetic genuine India Post delivery confirmation", ""),
    (83, "Dear HDFC Bank Customer, your monthly bank statement for September 2026 is sent to your registered email. Password is your 8-digit date of birth.", "legit", False, "", "en", "Synthetic genuine bank statement notice", ""),
    (84, "Your appointment with Dr. Mehta at Manipal Hospital is confirmed for 27-Oct-2026 at 11:30 AM. Reply CANCEL to reschedule.", "legit", False, "", "en", "Synthetic genuine hospital appointment confirmation", ""),
    (85, "Kotak Bank Alert: Rs. 500 debited at Metro Station UPI. Balance: Rs 15,200. Never share your UPI PIN or OTP.", "legit", False, "", "en", "Synthetic genuine small UPI debit alert", ""),
    (86, "Your Airtel mobile bill of Rs 599 for number 9876543210 is generated. Due date 02-Nov-2026. View bill on Airtel Thanks app.", "legit", False, "", "en", "Synthetic genuine telecom postpaid bill alert", ""),
    (87, "Flipkart: Your package containing Puma shoes is out for delivery with our wishmaster Ramesh. Share delivery PIN 4821 with him at delivery time.", "legit", False, "", "en", "Synthetic genuine delivery PIN message", ""),
    (88, "State Bank of India: Periodic KYC update reminder. As per RBI guidelines, please submit KYC documents at your home branch at your convenience.", "legit", False, "", "en", "Synthetic genuine KYC branch reminder without links", ""),
    (89, "Indian Railways: PNR 2849102143. Train 12626 Kerala Express. Confirmed Coach B2 Berth 35. Chart prepared.", "legit", False, "", "en", "Synthetic genuine IRCTC railway reservation alert", ""),
    (90, "Google Security Alert: A new sign-in on Windows PC was detected for your account. If this was you, no action needed.", "legit", False, "", "en", "Synthetic genuine Google security alert", ""),
    (91, "EPFO Alert: Monthly contribution of Rs 3,600 credited to your EPF account for September 2026. Total balance: Rs 2,45,000.", "legit", False, "", "en", "Synthetic genuine provident fund credit alert", ""),
    (92, "Dear Customer, Rs 10,000 withdrawn from ATM at MG Road on Canara Bank card XX8912. Call 18004250018 if not done by you.", "legit", False, "", "en", "Synthetic genuine ATM withdrawal alert", ""),
    (93, "Zomato: Delivery partner Arun has picked up your lunch order from Paradise Biryani. Arriving in 15 mins.", "legit", False, "", "en", "Synthetic genuine food delivery tracking alert", ""),
    (94, "Income Tax Department: Refund of Rs 4,820 for AY 2026-27 has been processed and credited to your validated bank account.", "legit", False, "", "en", "Synthetic genuine IT refund processed alert", ""),
    (95, "Punjab National Bank: Dear customer, maintenance activity scheduled on NetBanking on Sunday from 2 AM to 4 AM. Services will be briefly unavailable.", "legit", False, "", "en", "Synthetic genuine scheduled maintenance alert", ""),
    (96, "Indane Gas: Your LPG cylinder booking ref #48921 is confirmed. Cash on delivery amount Rs 805.", "legit", False, "", "en", "Synthetic genuine LPG refill booking confirmation", ""),
    (97, "SBI Card: Rs. 3,200 spent on your card XX4321 at RELIANCE RETAIL on 26-Oct-2026. Avail credit limit Rs 1,45,000.", "legit", False, "", "en", "Synthetic genuine credit card transaction SMS", ""),
    (98, "Delhivery: Package DEL98421 delivered. Thank you for shipping with Delhivery. Rate your experience on our app.", "legit", False, "", "en", "Synthetic genuine delivery completion confirmation", ""),
    (99, "Axis Bank: Your fixed deposit FD89230 of Rs 1,00,000 matures on 15-Nov-2026. Auto-renewal option is active.", "legit", False, "", "en", "Synthetic genuine FD maturity advisory", ""),
    (100, "Your password for Netflix was updated successfully. If you did not make this change, visit account settings.", "legit", False, "", "en", "Synthetic genuine password change confirmation", ""),
]

with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["id", "text", "label", "urgent_gold", "scam_type_gold", "language", "notes", "followup"])
    for row in MESSAGES:
        writer.writerow(row)

print(f"Generated {len(MESSAGES)} labeled messages into {csv_path}")
