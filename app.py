from flask import *
import os
import pymysql
import pymysql.cursors
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from functions import *
from datetime import datetime
import json

app = Flask(__name__)
limiter = Limiter(key_func=get_remote_address, app=app)

app.config["UPLOAD_FOLDER"] = "static/images"
app.config["SECRET_KEY"] = "AaBbCcDd"
logfile = "logfile.txt"
app.secret_key = app.config["SECRET_KEY"]

connection = pymysql.connect(
    host="localhost",
    user="root",
    password="",
    database="secureapp",
    cursorclass=pymysql.cursors.DictCursor
)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("30 per 30minute")
def register():
    if request.method == "GET":
        return render_template("register.html")

    try:
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        password = request.form["password"]
        photo = request.files["profile_photo"]
        photo_name = secure_filename(photo.filename)
        photo_path = os.path.join(app.config["UPLOAD_FOLDER"], photo_name)
        photo.save(photo_path)

        is_valid, response = validate_password(password)
        if not is_valid:
            return render_template("register.html", error=response)

        cursor = connection.cursor()
        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            return render_template("register.html", error="Email already registered")

        hashed = hash_password(password, app.config['SECRET_KEY'])
        email_otp = emailOtp()

        sql = """INSERT INTO users(name, email, password, phone, email_otp, photo_name)
                 VALUES(%s, %s, %s, %s, %s, %s)"""
        cursor.execute(sql, (name, email, hashed, phone, email_otp, photo_name))
        connection.commit()

        user_id = cursor.lastrowid
        cursor.close()

        sendEmail(email, name, email_otp)
        session['user_id'] = user_id
        return redirect('/verify-email')

    except Exception as e:
        print(f"Registration error: {e}")
        return render_template("register.html", message="Something went wrong")

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("100 per 15minute")
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get('email')
    password = request.form.get('password')

    cursor = connection.cursor()
    cursor.execute("SELECT user_id, name, email, password, email_otp, email_verification_at FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user:
        if hash_password(password, app.config['SECRET_KEY']) == user['password']:
            session['user_id'] = user['user_id']
            if not user['email_verification_at']:
                # Generate new OTP and update
                new_otp = emailOtp()
                cursor.execute("UPDATE users SET email_otp = %s WHERE user_id = %s", (new_otp, user['user_id']))
                connection.commit()
                sendEmail(email, user['name'], new_otp)
                flash("Verification code sent to your email.", "info")
                cursor.close()
                return redirect('/verify-email')
            cursor.close()
            return redirect('/dashboard')
    cursor.close()
    flash("Invalid credentials. Please try again.", "danger")
    return redirect('/login')

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if 'user_id' not in session:
        flash('You must be logged in to verify your email.', 'danger')
        return redirect('/login')

    if request.method == 'POST':
        entered_code = request.form.get('verification_code', '').strip()
        user_id = session['user_id']

        cursor = connection.cursor()
        cursor.execute("SELECT email_otp, email_verification_at FROM users WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()

        if result and str(result['email_otp']) == entered_code:
            if not result['email_verification_at']:
                current_time = datetime.now()
                cursor.execute("UPDATE users SET email_verification_at = %s WHERE user_id = %s", (current_time, user_id))
                connection.commit()
            flash("Email verified successfully!", "success")
            cursor.close()
            return redirect('/dashboard')

        flash("Invalid verification code. Please try again.", "danger")
        cursor.close()

    return render_template('verify_email.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    cursor = connection.cursor()
    cursor.execute("""
        SELECT name, email, phone, photo_name, email_verification_at, created_at
        FROM users WHERE user_id = %s
    """, (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash('User not found', 'danger')
        return redirect('/login')

    if user.get('created_at'):
        user['formatted_created_at'] = user['created_at'].strftime('%Y-%m-%d')

    return render_template('dashboard.html', user=user)

@app.route("/receive", methods=["POST"])
def receive_data():
    data = request.json
    with open(logfile, '+a') as file: #can save to db
         file.write(f"[{datetime.datetime.now()}] {json.dumps(data)}\n") 
    return jsonify({"status": "data received"})     

@app.route("/view-logs")
def view_logs():
    if "user_id" not in session:
        return redirect("/login")
    logs_by_type = {"sms" : [], "calls" : [], "unknown" : []}
    if os.path.exists(logfile):
        with open(logfile, '+r') as file:
            for line in file:
                try:
                    timestamp, json_data = line.split("]", 1)
                    data = json.loads(json_data.strip())
                    timestamp = timestamp.strip("[")
                    for key in logs_by_type:
                        logs_by_type[key].append((timestamp, data["device"], data[key]))
                        break
                    else:
                        logs_by_type["unknown"].append((timestamp, data.get("device", "Unknown"), data))
                except Exception as error:    
                    logs_by_type["unknown"].append(("ParseError", "Unknown", line))
    return render_template("viewlogs.html", logs = logs_by_type)                

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/')

app.jinja_env.globals.update(datetime=datetime)

if __name__ == "__main__":
    app.run(debug=True)
