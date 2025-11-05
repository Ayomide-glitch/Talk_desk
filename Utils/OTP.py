import os
import hmac
import hashlib
import base64
import pyotp
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

YOUR_SECRET = os.getenv("YOUR_SECRET")  # store this safely in .env
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def generate_otp(email):
    """Generate a 6-digit time-based OTP for a specific email"""
    h = hmac.new(YOUR_SECRET.encode(), email.encode(), hashlib.sha256)
    digest = h.digest()
    user_secret = base64.b32encode(digest).decode()
    totp = pyotp.TOTP(user_secret, digits=6, interval=120)
    return totp.now()

def verify_otp(email, otp):
    """Verify the OTP entered by the user"""
    h = hmac.new(YOUR_SECRET.encode(), email.encode(), hashlib.sha256)
    digest = h.digest()
    user_secret = base64.b32encode(digest).decode()
    totp = pyotp.TOTP(user_secret, digits=6, interval=120)
    return totp.verify(otp)

def send_otp_mail(email, otp):
    """Send OTP to user's email"""
    msg = MIMEText(f"This is your OTP to verify your account: {otp}")
    msg["Subject"] = "OTP Verification"
    msg["From"] = EMAIL_USER
    msg["To"] = email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)

print(pyotp.random_base32()[:6])