import smtplib
import random
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from email.utils import formataddr

load_dotenv()

EMAIL = os.getenv("EMAIL")  # noreply@vulnforge.app
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")  # Resend API key


def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(to_email: str, otp: str):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "VulnForge - Your OTP Code"
        msg["From"] = formataddr(("VulnForge 🛡", EMAIL))
        msg["To"] = to_email

        html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">

<style>

body {{
  font-family: Arial, sans-serif;
  background-color: #0a0a0a;
  margin: 0;
  padding: 40px;
  color: #ffffff;
}}

.container {{
  max-width: 500px;
  margin: 0 auto;
  background: #111111;
  border-radius: 10px;
  padding: 40px;
  border: 1px solid #00ff88;
}}

.header {{
  text-align: center;
}}

.header h1 {{
  color: #00ff88;
  margin: 0;
  font-size: 28px;
}}

.subtitle {{
  color: #aaaaaa;
  font-size: 14px;
  margin-top: 6px;
}}

.divider {{
  border: 1px solid #222222;
  margin: 25px 0;
}}

.content h2 {{
  text-align: center;
  color: #ffffff;
}}

.otp-box {{
  background-color: #1a1a1a;
  border-radius: 8px;
  padding: 25px;
  text-align: center;
  margin: 25px 0;
  border: 1px solid #00ff8844;
}}

.otp-code {{
  color: #00ff88;
  font-size: 36px;
  letter-spacing: 10px;
  font-family: Arial, sans-serif;
  margin: 0;
}}

.expiry {{
  text-align: center;
  color: #888888;
  font-size: 13px;
}}

.footer {{
  text-align: center;
  color: #444444;
  font-size: 11px;
}}

</style>

</head>

<body>

<div class="container">

<div class="header">
<h1>⚡ VulnForge</h1>
<p class="subtitle">Autonomous Penetration Testing Platform</p>
</div>

<hr class="divider">

<div class="content">

<h2>Your Verification Code</h2>

<div class="otp-box">
<h1 class="otp-code">{otp}</h1>
</div>

<p class="expiry">
This OTP expires in <b style="color:#ffffff;">10 minutes</b>
</p>

<p class="expiry">
If you didn't request this, ignore this email.
</p>

</div>

<hr class="divider">

<p class="footer">
© 2026 VulnForge. All rights reserved.
</p>

<p class="footer">
This is an automated email please do not reply.
</p>

</div>

</body>
</html>
"""

        msg.attach(MIMEText(html, "html"))

        # RESEND SMTP
        with smtplib.SMTP_SSL("smtp.resend.com", 465) as server:
            server.login("resend", EMAIL_PASSWORD)
            server.sendmail(EMAIL, to_email, msg.as_string())

        return True

    except Exception as e:
        print("Email error:", e)
        return False


if __name__ == "__main__":
    otp = generate_otp()
    send_otp_email("test@example.com", otp)
