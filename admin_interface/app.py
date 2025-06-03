from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import requests
from collections import defaultdict
from werkzeug.security import check_password_hash
import MySQLdb
import re
from datetime import datetime


app = Flask(__name__)
app.secret_key = '6f2b7f6e72b8d3a4d8c4c013d9b3b73f914e7cdbd33b44a29c02d45c5dd5e12f'

# Connexion MySQL
def get_connection():
    return MySQLdb.connect(
        host="db",
        user="root",
        password="root",
        database="flask_db"
    )

# Récupérer utilisateur
def get_user_by_email(email):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password, nom, prenom FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    conn.close()
    return user

def insert_rule(protocol, port, action, source_ip, destination_ip, comment):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO firewall_rules (protocol, port, action, source_ip, destination_ip, comment) VALUES (%s, %s, %s, %s, %s, %s)",
        (protocol, port, action, source_ip, destination_ip, comment)
    )
    conn.commit()
    conn.close()

def get_all_rules():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT protocol, port, action, source_ip, destination_ip, comment FROM firewall_rules ORDER BY id DESC")
    rules = cur.fetchall()
    conn.close()
    return rules

def add_rule():
    protocol = request.form.get('protocol')
    port = request.form.get('port')
    action = request.form.get('action')
    source_ip = request.form.get('source_ip') or "0.0.0.0/0"
    destination_ip = request.form.get('destination_ip') or "0.0.0.0/0"
    comment = request.form.get('comment')

    rule = {
        "protocol": protocol,
        "port": int(port),
        "action": action,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "comment": comment
    }

    try:
        response = requests.post(FIREWALL_API_URL, json=rule)
        if response.status_code == 200:
            flash("Règle ajoutée avec succès ✅", "success") # à modifier
            insert_rule(protocol, port, action, source_ip, destination_ip, comment)
        else:
            flash(f"Erreur : {response.json().get('error')}", "danger") # à modifier
    except Exception as e:
        flash(f"Erreur de connexion au conteneur firewall : {e}", "danger") # à modifier

    return redirect('/firewall')

def delete_rule():
    protocol = request.form.get('protocol')
    port = request.form.get('port')
    action = request.form.get('action')
    source_ip = request.form.get('source_ip') or "0.0.0.0/0"
    destination_ip = request.form.get('destination_ip') or "0.0.0.0/0"
    comment = request.form.get('comment')
    rule = {
        "protocol": protocol,
        "port": int(port),
        "action": action,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "comment": comment
    }
    if rule:
        try:
            response = requests.post("http://firewall:9000/delete_rule", json=rule)
            if response.status_code == 200:
                flash(f"Régle supprimée avec succès 🚫", "success") # à modifier
                conn = get_connection()
                cur = conn.cursor()
                cur.execute("DELETE FROM firewall_rules WHERE protocol = (%s) AND port = (%s) AND action = (%s) AND source_ip = (%s) AND destination_ip = (%s)",(protocol, port, action, source_ip, destination_ip))
                conn.commit()
                conn.close()
            else:
                flash(f"Erreur API : {response.json().get('error')}", "danger") # à modifier
        except Exception as e:
            flash(f"Erreur de communication avec l'API firewall : {e}", "danger") # à modifier
    else:
        flash("Régle invalide", "warning") # à modifier
    return redirect('/firewall')

def block_ip():
    ip = request.form.get('block_ip')
    if ip:
        try:
            response = requests.post("http://firewall:9000/block_ip", json={"ip": ip})
            if response.status_code == 200:
                flash(f"IP {ip} bloquée avec succès 🚫", "success") # à modifier
                conn = get_connection()
                cur = conn.cursor()
                cur.execute("INSERT INTO blocked_ips (ip_address) VALUES (%s)",(ip,))
                conn.commit()
                conn.close()
            else:
                flash(f"Erreur API : {response.json().get('error')}", "danger") # à modifier
        except Exception as e:
            flash(f"Erreur de communication avec l'API firewall : {e}", "danger") # à modifier
    else:
        flash("Adresse IP invalide", "warning") # à modifier
    return redirect('/firewall')

def unblock_ip():
    ip = request.form.get('unblock_ip')
    if ip:
        try:
            response = requests.post("http://firewall:9000/unblock_ip", json={"ip": ip})
            if response.status_code == 200:
                flash(f"IP {ip} debloquée avec succès 🚫", "success") # à modifier
                conn = get_connection()
                cur = conn.cursor()
                cur.execute("DELETE FROM blocked_ips WHERE ip_address = (%s)",(ip,))
                conn.commit()
                conn.close()
            else:
                flash(f"Erreur API : {response.json().get('error')}", "danger") # à modifier
        except Exception as e:
            flash(f"Erreur de communication avec l'API firewall : {e}", "danger") # à modifier
    else:
        flash("Adresse IP invalide", "warning") # à modifier
    return redirect('/firewall')

def get_blocked_ips():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT ip_address, blocked_at FROM blocked_ips ORDER BY id DESC")
    blocked_ips = cur.fetchall()
    conn.close()
    return blocked_ips


@app.route('/')
def home():
    return render_template('signin.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = get_user_by_email(email)
        if user and check_password_hash(user[2], password):
            session['email'] = user[1]
            flash('Connexion réussie ✅', 'success') # à modifier
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou mot de passe incorrect ❌', 'danger') # à modifier

    return render_template('signin.html')

@app.route('/logout')
def logout():
    # Supprime toutes les données de session
    session.clear()
    flash("Déconnexion réussie 👋", "info") # à modifier
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        email = session['email']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT nom FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        cur.execute("SELECT client_ip, host_cible, uri, method, attack_type, status, created_at FROM waf_logs ORDER BY created_at DESC LIMIT 5")
        logs = cur.fetchall()
        cur.execute("SELECT ip_address, blocked_at FROM blocked_ips ORDER BY blocked_at DESC LIMIT 10")
        blocked_ips = cur.fetchall()
        conn.close()
        if user_data:
            nom = user_data[0]
            return render_template('index.html', nom=nom, logs=logs, blocked_ips=blocked_ips)
    return redirect(url_for('login'))

@app.route('/logs')
def logs():
    if 'email' in session:
        email = session['email']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT nom FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        cur.execute("SELECT client_ip, host_cible, uri, method, attack_type, status, created_at FROM waf_logs ORDER BY created_at DESC LIMIT 100")
        logs = cur.fetchall()
        conn.close()
        if user_data:
            nom = user_data[0]
            return render_template('logs.html', nom=nom, logs=logs)
    return redirect(url_for('login'))

@app.route("/api/traffics/hourly")
def hourly_traffic():
    authorized = defaultdict(int)
    blocked = defaultdict(int)

    # Date du jour au format dans les logs : "29/May/2025"
    today_str = datetime.now().strftime("%d/%b/%Y")

    with open("/mnt/nginx-logs/nginx.log", "r") as f:
        for line in f:
            # Ne traiter que les lignes du jour actuel
            if today_str in line:
                # Extraire l'heure
                match = re.search(r"\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):\d{2}:\d{2}", line)
                if match:
                    hour = match.group(4)  # 4e groupe = heure

                    # Extraire le code HTTP
                    code_match = re.search(r'" - (\d{3})$', line.strip())
                    if code_match:
                        code = code_match.group(1)
                        if code in ["200", "304"]:
                            authorized[hour] += 1
                        elif code == "403":
                            blocked[hour] += 1

    # Heures de 00 à 23
    hours = [f"{h:02d}" for h in range(24)]
    authorized_data = [authorized[h] for h in hours]
    blocked_data = [blocked[h] for h in hours]

    return jsonify({
        "hours": hours,
        "authorized": authorized_data,
        "blocked": blocked_data
    })

@app.route("/api/attacks/types")
def attack_type_stats():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT attack_type, COUNT(*) FROM waf_logs GROUP BY attack_type")
    rows = cur.fetchall()
    conn.close()

    stats = {row[0]: row[1] for row in rows}
    return jsonify(stats)

FIREWALL_API_URL = "http://firewall:9000/add_rule"

@app.route('/firewall', methods=['GET', 'POST'])
def firewall():
    if 'email' in session:
        email = session['email']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT nom FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        conn.close()
        if request.method == 'POST':
            form_type = request.form.get('form_type')
            if form_type == 'block_ip':
                block_ip()
            elif form_type == 'unblock_ip' :
                unblock_ip()
            elif form_type == 'delete_rule' :
                delete_rule()
            else:
                add_rule()
        rules = get_all_rules()
        blocked_ips=get_blocked_ips()
        if user_data:
            nom = user_data[0]
            return render_template('firewall.html', rules=rules, nom=nom, blocked_ips=blocked_ips)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
