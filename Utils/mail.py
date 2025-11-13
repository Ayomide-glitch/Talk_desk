import datetime

import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

from dotenv import load_dotenv
load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def send_email(receiver_email, subject, body):
    msg = MIMEMultipart()
    msg["From"] = EMAIL_USER
    msg["To"] = receiver_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False


def get_address(ip_address):
    url = f"https://ipapi.co/{ip_address}/json/"
    addr = requests.get(url).json()
    if addr["error"]:
        return None
    city = addr.get('city')
    region = addr.get('region')
    country = addr.get('country')

    print(addr)

    address = f"near {city}, {region}, {country}"
    return address

def send_login_alert(user_email, ip_address):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    address = get_address(ip_address)
    body = f"A new login was detected on your account {address} at {timestamp}"
    subject = "Login Alert"

    if send_email(user_email,subject=subject,body=body):
        return True

    return False
def message_sent(email,subjects,content,file_url):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject= "Message sent"
    body = f"Details: {subjects}\n\n{content}\n\n{file_url} at {timestamp}"

    if send_email(email,subject,body):
        return True

    return False

def send_close_ticket(user_email):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = f"Your ticket has been closed by the admin at {timestamp}"
    subject = "Closing Ticket"

    if send_email(user_email,subject,body):
        return True

    return False

