from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
import re,openai
import time,g4f
import socket,requests
from scapy.all import ARP, Ether, srp
from subprocess import Popen, PIPE
import nmap


app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
openai.api_key="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"

try:
    db_connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="vuln"
    )
    cursor = db_connection.cursor()
except mysql.connector.Error as err:
    print(f"Error connecting to the database: {err}")
@app.route('/')
def welcome():
    return render_template('index.html')


@app.route('/function1')
def function1():
    sessionKaNaam = (session.get('user_id'))
    if sessionKaNaam=='':
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    else:
        return render_template('function1.html')


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/popvuln')
def popvuln():
    return render_template('popvuln.html')


@app.route('/devices', methods=['GET', 'POST'])
def devices(): 
        x=socket.getfqdn()
        target_ip = f"{socket.gethostbyname(x)}/24"
        try:
            devices = maclookup(target_ip)

            return render_template('devices.html', devices=devices)
        except Exception as e:
            flash(f"An error occurred during the scan: {str(e)}", 'error')
            return render_template('devices.html')



def scan_network1(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sn')

    devices = []
    for host in nm.all_hosts():
        devices.append({'ip': host, 'mac': maclookup(host)})

    return devices


def get_hostname(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "Unable to resolve hostname"
    

def maclookup(ip):
    
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'mac_name': name1( received.hwsrc) })
    
    return devices

def name1(bb):
    mac1=bb[:8].replace(':','').upper()
    url=f"https://api.macvendors.com/{mac1}"
    response=requests.get(url)
    if response.text!="":
      return response.text
    else:
      return "unknown device"




@app.route('/contact')
def contact():
    return render_template('contact.html')


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
        session['user_id'] = result[1]
        is_admin = check_admin(result[1])
        session['is_admin'] = is_admin
        print(f'session[\'user_id\']: {session.get("user_id")}')
        print(f'session[\'is_admin\']: {session.get("is_admin")}')
        flash('Login successful!', 'success')
        return redirect(url_for('function1'))
    else:
        flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')

def check_admin(user_id):
    query = "SELECT COUNT(*) FROM admin_tb WHERE username = %s"
    cursor.execute(query, (user_id,))
    result = cursor.fetchone()

    return result and result[0] > 0

@app.route('/admin')

def admin():
    sessionKaNaam = (session.get('user_id'))
    if sessionKaNaam=='':
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    else:
        print(f'session[\'is_admin\']: {session.get("is_admin")}')  # Add this line for debugging

        if 'user_id' not in session or ('is_admin' not in session or not session['is_admin']):
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('login'))

        user_details = get_user_details()
        cve_entries = get_cve_details()

        return render_template('adminpage.html', user_details=user_details, cve_details=cve_entries)

def get_user_details():
    try:
        query = "SELECT * FROM user_details"
        cursor.execute(query)
        user_details = cursor.fetchall()
        return user_details
    except mysql.connector.Error as e:
        print(f"Error fetching user details: {e}")
        return []

def get_cve_details():
    try:
        query = "SELECT cve_id, description FROM cve_entries "
        cursor.execute(query)
        cve_details = cursor.fetchall()
        if cve_details:
            print("Fetched CVE details successfully.")
        else:
            print("No CVE details found.")
        return cve_details
    except mysql.connector.Error as e:
        print(f"Error fetching CVE details: {e}")
        return []

@app.route('/delete_user/<user_id>')
def delete_user(user_id):
    query1 = "DELETE FROM user_details WHERE username = %s"
    cursor.execute(query1, (user_id,))
    return redirect(url_for('admin'))  

@app.route('/delete_cve/<cve_id>')
def delete_cve(cve_id):
    pass


def register(username, password):
    email = request.form['logemail']
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    query = "SELECT * FROM user_details WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()

    if result:
        return render_template('login.html', msg="Username already exists. Please choose another.")
    else:
        query = "INSERT INTO user_details (username, hashed_password,user_email) VALUES (%s, %s,%s)"
        cursor.execute(query, (username, hashed_password, email))
        db_connection.commit()

        return login1(username, password)

@app.route('/insta')
def insta():
    return render_template('result1.html')


@app.route('/logout')
def logout():
    session['user_id']=''
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
            a = time.time()
            vulnerabilities = scan_network(target_ip)
            b = time.time()
            c = b - a
            return render_template('result.html', vulnerabilities=vulnerabilities)
        except Exception as e:
            flash(f"An error occurred during the scan: {str(e)}", 'error')
            return redirect(url_for('index1'))

    return render_template('index1.html')


def scan_network(target_ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, arguments='-sV -Pn --script vulners')
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
            vulnerabilities.append({'cve_id': cve_id, 'description': description, 'solution': response1(description)})

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

def response1(description):
    g4f.debug.logging = True 
    g4f.check_version = False
    response = g4f.ChatCompletion.create(
        model=g4f.models.gpt_4,
        messages=[{"role": "root", "content": f"explain this in human understandable format without comments without any comments, only need the answer: {description}"}],
    )  
    return response


if __name__ == '__main__':
    try:
        app.run(debug=True)
    finally:
        db_connection.close()
