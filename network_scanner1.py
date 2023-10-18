from flask import Flask, render_template, request,session, redirect, url_for,flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
import nmap
import re

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'your_secret_key_here'

db_connection = mysql.connector.connect(
    host="undeadeyes12.mysql.pythonanywhere-services.com",
    user="undeadeyes12",
    password="hahahuhu123",
    database="undeadeyes12$vuln"
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
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['logname']
        password = request.form['logpass']
        action = request.form.get('action')  # Get the value of the 'action' field

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
        session['username'] = username
        flash('Login successful!', 'success')
        return redirect(url_for('index1'))
    else:
        flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')

def register(username, password):
    query = "SELECT * FROM user_details WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()

    if result:
        flash('Username already exists. Please choose another username.', 'error')
    else:
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        query = "INSERT INTO user_details (username, hashed_password) VALUES (%s, %s)"
        cursor.execute(query, (username, hashed_password))
        db_connection.commit()

        session['username'] = username
        flash('Registration successful!', 'success')
        return redirect(url_for('index1'))

    return render_template('login.html')



@app.route('/index1', methods=['GET', 'POST'])
def index1():
    if request.method == 'POST':
        target_ip = request.form['target_ip']
        vulnerabilities = scan_network(target_ip)
        return render_template('result.html', vulnerabilities=vulnerabilities)
    return render_template('index1.html')

def scan_network(target_ip):
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


def get_cve_description(cve_id):
    cursor.execute("SELECT description FROM cve_entries WHERE cve_id = %s", (cve_id,))
    result = cursor.fetchone()
    if result:
        return result[0]
    else:
        return "CVE description not found for " + cve_id

if __name__ == '__main__':
    try:
        app.run(debug=True)
    finally:
        db_connection.close()