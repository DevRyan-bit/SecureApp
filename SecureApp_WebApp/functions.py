import re
import hashlib
import random
import string

# Sending an email
import smtplib
from email.mime.text import MIMEText

# hash password function
def hash_password(password, secret_key):
    hashar = hashlib.md5()
    salted_password = secret_key + password
    hashar.update(salted_password.encode("utf-8"))
    hashedPassword = hashar.hexdigest()
    return hashedPassword

# validate password -
def validate_password(password):
    """
    Validate password strength:
    -At atleast 8 characters
    -At least one uppercase letter
    -At least one lowercase letter
    -At least one digit
    -At least one special character
    """
    if len(password) < 8:
        return False, "PASSWORD MUST BE AT LEAST 8 CHARACTERS LONG"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*()<>?\":{]|<>", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

# Function to generate verification code
def emailOtp():
    length = 6 
    character = string.digits #+ string.ascii_letters
    return "".join(random.choices(character, k=length))


# Emial config
port = 587
smtp_server = "mail.coding.co.ke"
password = "M@dc@mCyb3r2025"
sender_email = "cyberclass@coding.co.ke"

def sendEmail(email, name, code):
    text = f"""
Hi {name}

Thank you for registering an account at Secure App !
Use the code below to activate your account.
{code}

If you have any challenges, contact us on info@coding.co.ke

"""
    message = MIMEText(text, "plain")
    message["Subject"] = "Verify your Account"
    message["From"] = sender_email
    message["To"] = email

    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, email, message.as_string())
        print("Email sent")
        server.close()