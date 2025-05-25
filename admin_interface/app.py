from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash
import MySQLdb

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
            flash('Connexion réussie ✅', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou mot de passe incorrect ❌', 'danger')

    return render_template('signin.html')

@app.route('/logout')
def logout():
    # Supprime toutes les données de session
    session.clear()
    flash("Déconnexion réussie 👋", "info")
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        email = session['email']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT nom FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        cur.execute("SELECT client_ip, host_cible, uri, method, attack_type, status, created_at FROM waf_logs ORDER BY created_at DESC LIMIT 3")
        logs = cur.fetchall()
        conn.close()
        if user_data:
            nom = user_data[0]
            return render_template('index.html', nom=nom, logs=logs)
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
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
