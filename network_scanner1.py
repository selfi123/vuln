from flask import Flask, render_template, request,session, redirect, url_for,flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
import nmap
import re,time
from flask_session import Session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 

db_connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="vuln"
)
cursor = db_connection.cursor()

@app.route('/')
def welcome():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    cursor.execute("SELECT * FROM user_details WHERE user_id = %s", (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        return User(user_data[0], user_data[1])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['logname']
        password = request.form['logpass']
    
        action = request.form.get('action')  

        if action == 'register':
            return register(username, password)
        elif action == 'login1':
            return login1(username, password)

    return render_template('login.html')

def login1(username, password):
    query = "SELECT * FROM user_details WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()

    if result and check_password_hash(result[2], password):
        user_obj = User(result[0], result[1])
        login_user(user_obj)
        session['username'] = username
        flash('Login successful!', 'success')
        return redirect(url_for('index1'))
    else:
        flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')

def register(username, password):
    email=request.form['logemail']
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    query = "SELECT * FROM user_details WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()

    if result:
            return render_template('login.html',msg="Username already exists. Please choose another.")
    else:
        query = "INSERT INTO user_details (username, hashed_password,user_email) VALUES (%s, %s,%s)"
        cursor.execute(query, (username, hashed_password,email))
        db_connection.commit()

        return login1(username, password)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('welcome'))

@app.route('/loading')
def loading():
    return render_template('loading.html')


@app.route('/index1', methods=['GET', 'POST'])
def index1():
    if request.method == 'POST':
        target_ip = request.form['target_ip']
        try:
            a=time.time()
            vulnerabilities = scan_network(target_ip)
            b=time.time()
            c=b-a
            return render_template('result.html', vulnerabilities=vulnerabilities)
        except Exception as e:
            flash(f"An error occurred during the scan: {str(e)}", 'error')
            return redirect(url_for('index1'))

    return render_template('index1.html')
         
def scan_network(target_ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, arguments='-sV --script vulners')
        vulnerabilities = []
        unique_cve_ids = set()

        for host in nm.all_hosts():
            host_data = nm[host]
            if 'tcp' in host_data:
                for port, port_data in host_data['tcp'].items():
                    if 'script' in port_data and 'vulners' in port_data['script']:
                        vulners_output = port_data['script']['vulners']
                        cve_ids = re.findall(r'CVE-\d+-\d+', vulners_output)
                        for cve_id in cve_ids:
                            unique_cve_ids.add(cve_id)

        for cve_id in unique_cve_ids:
            description = get_cve_description(cve_id)
            vulnerabilities.append({'cve_id': cve_id, 'description': description})

        return vulnerabilities
    except nmap.NmapError as me:
        raise me


def get_cve_description(cve_id):
    try:
        cursor.execute("SELECT description FROM cve_entries WHERE cve_id = %s", (cve_id,))
        result = cursor.fetchone()
        if result:
            return result[0]
        else:
            return "CVE description not found for " + cve_id
    except mysql.connector.Error as me:
        raise me
    
if __name__ == '__main__':
    try:
        app.run(debug=True)
    finally:
        db_connection.close()