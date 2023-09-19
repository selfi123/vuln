from flask import Flask, render_template, request
import mysql.connector
import nmap
import re

app = Flask(__name__)
db_connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="vuln"
)
cursor = db_connection.cursor()
@app.route('/', methods=['GET', 'POST'])
def index():
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
    app.run(debug=True)
