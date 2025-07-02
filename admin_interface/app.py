from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import requests
from collections import defaultdict
from werkzeug.security import check_password_hash
import MySQLdb
import re
from datetime import datetime
from json import loads, dumps
import logging
import os
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from jinja2 import Template

app = Flask(__name__)
app.secret_key = '6f2b7f6e72b8d3a4d8c4c013d9b3b73f914e7cdbd33b44a29c02d45c5dd5e12f'
app.logger.setLevel(logging.DEBUG)

def check_modsec_rules(file_path):
    script_path = '/app/rules_check/crs-rules-check/rules-check.py'
    tags_path = '/app/rules_check/APPROVED_TAGS'
    try:
        result = subprocess.run(['python3', script_path, "-r", file_path, "-t", tags_path, "-v", "v4.15.0-5-gabc63791"], capture_output=True, text=True, check=True)
        return True, result.stdout  # The script's output (validation result)
    except subprocess.CalledProcessError as e:
        return False, f"Error validating rules: {str(e)}"
    except Exception as ex:
        return False, f"Unexpected error: {str(ex)}"

# WAF Manager Integration
@dataclass
class WebApp:
    name: str
    domain: str
    backend_host: str
    backend_port: int
    ssl_enabled: bool = False
    custom_rules: bool = True
    rate_limit: Optional[str] = None
    status: str = "active"
    created_at: Optional[str] = None

class WAFManager:
    def __init__(self, 
                 nginx_conf_dir: str = "/etc/nginx/conf.d",
                 modsec_rules_dir: str = "/etc/nginx/modsec/apps",
                 custom_rules_dir: str = "/etc/nginx/modsec/app_rules",
                 apps_config_file: str = "/etc/waf/apps.json"):
        self.nginx_conf_dir = Path(nginx_conf_dir)
        self.modsec_rules_dir = Path(modsec_rules_dir)
        self.custom_rules_dir = Path(custom_rules_dir)
        self.apps_config_file = Path(apps_config_file)
        
        # Create directories if they don't exist
        self.nginx_conf_dir.mkdir(parents=True, exist_ok=True)
        self.modsec_rules_dir.mkdir(parents=True, exist_ok=True)
        self.custom_rules_dir.mkdir(parents=True, exist_ok=True)
        self.apps_config_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.logger = app.logger
        
        # Load existing apps
        self.apps = self._load_apps()
    
    def _load_apps(self) -> Dict[str, WebApp]:
        """Load existing apps configuration"""
        if not self.apps_config_file.exists():
            return {}
        
        try:
            with open(self.apps_config_file, 'r') as f:
                data = json.load(f)
                return {name: WebApp(**config) for name, config in data.items()}
        except Exception as e:
            self.logger.error(f"Error loading apps config: {e}")
            return {}
    
    def _save_apps(self):
        """Save apps configuration to file"""
        data = {name: asdict(app) for name, app in self.apps.items()}
        try:
            with open(self.apps_config_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving apps config: {e}")
    
    def add_app(self, app: WebApp) -> bool:
        """Add a new web application"""
        try:
            # Set creation timestamp
            app.created_at = datetime.now().isoformat()
            
            # Generate nginx server block
            self._generate_nginx_config(app)
            
            # Generate custom ModSecurity rules if provided
            if app.custom_rules:
                self._generate_modsec_rules(app)
                open(f'/etc/nginx/modsec/app_rules/{app.name}_custom_modsec_rules.conf','a').close()
            
            # Update apps registry
            self.apps[app.name] = app
            self._save_apps()
            
            # Save to database
            self._save_app_to_db(app)
            
            self.logger.info(f"Added app: {app.name} ({app.domain})")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding app {app.name}: {e}")
            return False
    
    def remove_app(self, app_name: str) -> bool:
        """Remove a web application"""
        if app_name not in self.apps:
            self.logger.warning(f"App {app_name} not found")
            return False
        
        try:
            app = self.apps[app_name]
            
            # Remove nginx config
            nginx_file = self.nginx_conf_dir / f"{app_name}.conf"
            if nginx_file.exists():
                nginx_file.unlink()
            
            # Remove custom rules
            custom_rules_file = Path(f'/etc/nginx/modsec/app_rules/{app.name}_custom_modsec_rules.conf')
            if custom_rules_file.exists():
                custom_rules_file.unlink()
            
            # Remove ModSecurity rules
            modsec_file = self.modsec_rules_dir / f"{app_name}.conf"
            if modsec_file.exists():
                modsec_file.unlink()
            
            # Remove from registry
            del self.apps[app_name]
            self._save_apps()
            
            # Remove from database
            self._remove_app_from_db(app_name)
            
            self.logger.info(f"Removed app: {app_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error removing app {app_name}: {e}")
            return False
    
    def _generate_nginx_config(self, app: WebApp):
        """Generate nginx server block configuration"""
        template_str = """
# {{ app.name }} - Generated automatically
server {
    listen 80;
    {% if app.ssl_enabled %}
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/{{ app.name }}.crt;
    ssl_certificate_key /etc/ssl/private/{{ app.name }}.key;
    {% endif %}
    
    server_name {{ app.domain }};
    
    # ModSecurity configuration
    modsecurity on;
    {% if not app.custom_rules %}
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
    {% endif %}
    {% if app.custom_rules %}
    modsecurity_rules_file /etc/nginx/modsec/apps/{{ app.name }}.conf;
    {% endif %}
    
    # Rate limiting
    {% if app.rate_limit %}
    limit_req zone={{ app.rate_limit }};
    {% endif %}
    
    # Logging
    # access_log /var/log/nginx/{{ app.name }}_access.log main;
    # error_log /var/log/nginx/{{ app.name }}_error.log;
    
    location / {
        # Security headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        
        # Backend proxy
        proxy_pass http://{{ app.backend_host }}:{{ app.backend_port }}/;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }
    
    # Error pages
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}
"""
        
        template = Template(template_str)
        config_content = template.render(app=app)
        
        config_file = self.nginx_conf_dir / f"{app.name}.conf"
        with open(config_file, 'w') as f:
            f.write(config_content)
    
    def _generate_modsec_rules(self, app: WebApp):
        """Generate custom ModSecurity rules for the app"""
        if not app.custom_rules:
            return
        
        rules_content = f"""
# Custom ModSecurity rules for {app.name}
# Generated automatically

# Include base configuration
Include /etc/nginx/modsec/modsecurity.conf
Include /usr/local/modsecurity-crs/crs-setup.conf
Include /usr/local/modsecurity-crs/rules/*.conf
Include /etc/nginx/modsec/app_rules/{app.name}_custom_modsec_rules.conf
"""
        
        rules_file = self.modsec_rules_dir / f"{app.name}.conf"
        with open(rules_file, 'w') as f:
            f.write(rules_content)
    
    def _save_app_to_db(self, app: WebApp):
        """Save app configuration to database"""
        try:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO managed_apps 
                (name, domain, backend_host, backend_port, ssl_enabled, custom_rules, rate_limit, status, created_at) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                app.name, app.domain, app.backend_host, app.backend_port,
                app.ssl_enabled, app.custom_rules, app.rate_limit, app.status, app.created_at
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Error saving app to database: {e}")
    
    def _remove_app_from_db(self, app_name: str):
        """Remove app from database"""
        try:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("DELETE FROM managed_apps WHERE name = %s", (app_name,))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Error removing app from database: {e}")
    
    def reload_nginx(self) -> bool:
        """Reload nginx configuration"""
        response = requests.post("http://waf:5001/trigger",json={"code": 1})
        if response.status_code == 200:
            app.logger.info(response.json().get('status'))
            response2 = requests.post("http://waf:5001/trigger",json={"code": 2})
            if response2.status_code == 200:
                return True
            else:
                app.logger.error(f"{response.json()}")
                return False

        else:
            app.logger.error(f"{response.json()}")
            return False
    
    def list_apps(self) -> List[WebApp]:
        """List all registered applications"""
        return list(self.apps.values())
    
    def get_app(self, name: str) -> Optional[WebApp]:
        """Get application by name"""
        return self.apps.get(name)

# Initialize WAF Manager
waf_manager = WAFManager()

# Database functions (existing functions remain the same)
def get_connection():
    return MySQLdb.connect(
        host="db",
        user="root",
        password="root",
        database="flask_db"
    )

def get_user_by_email(email):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password, nom, prenom FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    conn.close()
    return user


# App management functions
def get_all_managed_apps():
    """Get all managed applications from database"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT name, domain, backend_host, backend_port, ssl_enabled, 
               custom_rules, rate_limit, status, created_at 
        FROM managed_apps ORDER BY created_at DESC
    """)
    apps = cur.fetchall()
    conn.close()
    return apps

def get_app_stats():
    """Get statistics about managed applications"""
    conn = get_connection()
    cur = conn.cursor()
    
    # Total apps
    cur.execute("SELECT COUNT(*) FROM managed_apps")
    total_apps = cur.fetchone()[0]
    
    # Active apps
    cur.execute("SELECT COUNT(*) FROM managed_apps WHERE status = 'active'")
    active_apps = cur.fetchone()[0]
    
    # Apps with SSL
    cur.execute("SELECT COUNT(*) FROM managed_apps WHERE ssl_enabled = 1")
    ssl_apps = cur.fetchone()[0]
    
    # Apps with custom rules
    cur.execute("SELECT COUNT(*) FROM managed_apps WHERE custom_rules IS NOT NULL")
    custom_rules_apps = cur.fetchone()[0]
    
    conn.close()
    
    return {
        'total_apps': total_apps,
        'active_apps': active_apps,
        'ssl_apps': ssl_apps,
        'custom_rules_apps': custom_rules_apps
    }

# firewall functions
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
            flash("Règle ajoutée avec succès ✅", "success")
            insert_rule(protocol, port, action, source_ip, destination_ip, comment)
        else:
            flash(f"Erreur : {response.json().get('error')}", "danger")
    except Exception as e:
        flash(f"Erreur de connexion au conteneur firewall : {e}", "danger")

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
                flash(f"Régle supprimée avec succès 🚫", "success")
                conn = get_connection()
                cur = conn.cursor()
                cur.execute("DELETE FROM firewall_rules WHERE protocol = (%s) AND port = (%s) AND action = (%s) AND source_ip = (%s) AND destination_ip = (%s)",(protocol, port, action, source_ip, destination_ip))
                conn.commit()
                conn.close()
            else:
                flash(f"Erreur API : {response.json().get('error')}", "danger")
        except Exception as e:
            flash(f"Erreur de communication avec l'API firewall : {e}", "danger")
    else:
        flash("Régle invalide", "warning")
    return redirect('/firewall')

def block_ip():
    ip = request.form.get('block_ip')
    if ip:
        try:
            response = requests.post("http://firewall:9000/block_ip", json={"ip": ip})
            if response.status_code == 200:
                flash(f"IP {ip} bloquée avec succès 🚫", "success")
                conn = get_connection()
                cur = conn.cursor()
                cur.execute("INSERT INTO blocked_ips (ip_address) VALUES (%s)",(ip,))
                conn.commit()
                conn.close()
            else:
                flash(f"Erreur API : {response.json().get('error')}", "danger")
        except Exception as e:
            flash(f"Erreur de communication avec l'API firewall : {e}", "danger")
    else:
        flash("Adresse IP invalide", "warning")
    return redirect('/firewall')

def unblock_ip():
    ip = request.form.get('unblock_ip')
    if ip:
        try:
            response = requests.post("http://firewall:9000/unblock_ip", json={"ip": ip})
            if response.status_code == 200:
                flash(f"IP {ip} debloquée avec succès 🚫", "success")
                conn = get_connection()
                cur = conn.cursor()
                cur.execute("DELETE FROM blocked_ips WHERE ip_address = (%s)",(ip,))
                conn.commit()
                conn.close()
            else:
                flash(f"Erreur API : {response.json().get('error')}", "danger")
        except Exception as e:
            flash(f"Erreur de communication avec l'API firewall : {e}", "danger")
    else:
        flash("Adresse IP invalide", "warning")
    return redirect('/firewall')

def get_blocked_ips():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT ip_address, blocked_at FROM blocked_ips ORDER BY id DESC")
    blocked_ips = cur.fetchall()
    conn.close()
    return blocked_ips

# WAF rules functions
def get_all_waf_rules(page=1, per_page=15, filters=None):
    conn = get_connection()
    cur = conn.cursor()

    offset = (page - 1) * per_page
    query = "SELECT rule_id, origin_file, status, variables, actions, description FROM waf_rules WHERE 1=1"
    params = []

    count_query = "SELECT COUNT(*) FROM waf_rules WHERE 1=1"
    count_params = []

    if filters:
        if filters.get("selected_app"):
            query += " AND (origin_file LIKE %s OR origin_file NOT LIKE '%%custom%%')"
            count_query += " AND (origin_file LIKE %s OR origin_file NOT LIKE '%%custom%%')"
            params.append(f'/etc/nginx/modsec/app_rules/{filters["selected_app"]}_custom_modsec_rules.conf')
            count_params.append(f'/etc/nginx/modsec/app_rules/{filters["selected_app"]}_custom_modsec_rules.conf')

        if filters.get("status"):
            query += " AND status = %s"
            count_query += " AND status = %s"
            params.append(filters["status"])
            count_params.append(filters["status"])

        if filters.get("search"):
            search_term = f"%{filters['search']}%"
            search_field = filters.get("search_field", "all")

            if search_field == "all":
                query += " AND (origin_file LIKE %s OR description LIKE %s OR variables LIKE %s OR actions LIKE %s)"
                count_query += " AND (origin_file LIKE %s OR description LIKE %s OR variables LIKE %s OR actions LIKE %s)"
                params.extend([search_term, search_term, search_term, search_term])
                count_params.extend([search_term, search_term, search_term, search_term])
            elif search_field == "origin file":
                query += " AND origin_file LIKE %s"
                count_query += " AND origin_file LIKE %s"
                params.append(search_term)
                count_params.append(search_term)
            elif search_field == "description":
                query += " AND description LIKE %s"
                count_query += " AND description LIKE %s"
                params.append(search_term)
                count_params.append(search_term)
            elif search_field == "variables":
                query += " AND variables LIKE %s"
                count_query += " AND variables LIKE %s"
                params.append(search_term)
                count_params.append(search_term)
            elif search_field == "actions":
                query += " AND actions LIKE %s"
                count_query += " AND actions LIKE %s"
                params.append(search_term)
                count_params.append(search_term)

    query += " ORDER BY rule_id ASC LIMIT %s OFFSET %s"
    params.extend([per_page, offset])

    cur.execute(query, tuple(params))
    rules = cur.fetchall()

    cur.execute(count_query, tuple(count_params))
    total_rules = cur.fetchone()[0]

    conn.close()
    return rules, total_rules

def insert_waf_rule_in_file(app, id, description, var, op, act):
    with open(f"/etc/nginx/modsec/app_rules/{app}_custom_modsec_rules.conf",'a') as f:
        lines = description.splitlines()
        comment = ["#" + line for line in lines]
        c_description = "\n".join(comment)
        variables = "|".join(loads(var))
        operators = '"' + op + '"'
        #if "OWASP-CRS" not in loads(act): # tag:'OWASP_CRS',ver:'OWASP_CRS/4.16.0-dev'
        actions = ",\\\n    ".join(loads(act))
        if "id" in actions:
            flash("id is generated automatically, don't include it in actions", "error")
            return False
        actions = "id:" + str(id) + ",\\\n    " + actions
        f.write(c_description + '\n')
        f.write(f'SecRule {variables} {operators} \\\n    "{actions}"\n\n')
        return True
    #is_valid, message = check_modsec_rules(f"/etc/nginx/modsec/app_rules/{app}_custom_modsec_rules.conf")

    #if not is_valid:
     #   flash(f"Erreur de validation ModSecurity : {message}", "danger")
      #  return
  #  else:
   #     flash("Règles ModSecurity validées avec succès ✅", "success")

def insert_waf_rule(app, description, variables, operators, actions):
#    try:
#        if not insert_waf_rule_in_file(app, description, variables, operators, actions):
#            return
#        flash('Rule added successfully!','success')
#    except Exception as e:
#        flash(f'Something went wrong {e}', 'error')
#        return
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT MAX(rule_id) FROM waf_rules WHERE origin_file LIKE '%custom%'")
    current_rule_id = cur.fetchone()[0]
    if current_rule_id is None:
        current_rule_id = 0
    elif current_rule_id >= 99999:
        flash('You have reach the max number of custom rules', 'error')

    try:
        if not insert_waf_rule_in_file(app,current_rule_id+1, description, variables, operators, actions):
            return
        flash('Rule added successfully!','success')
    except Exception as e:
        flash(f'Something went wrong {e}', 'error')
        return

    cur.execute("INSERT INTO waf_rules (rule_id, description, variables, operators, actions, origin_file) VALUES (%s, %s, %s, %s, %s, %s)", 
                (current_rule_id + 1, description, variables, operators, actions, f"/etc/nginx/modsec/app_rules/{app}_custom_modsec_rules.conf"))
    conn.commit()
    conn.close()

def delete_waf_rule_from_file(file_path, rule_text):
    with open(file_path, 'r') as f:
        content = f.read()

    if rule_text in content:
        new_content = content.replace(rule_text, '')
        with open(file_path, 'w') as f:
            f.write(new_content)
        flash("Rule deleted successfully.", "success")
        return True
    else:
        flash("Rule text not found in the file.", "error")
        return False

def delete_waf_rule(app, rule_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT origin_file FROM waf_rules WHERE rule_id = %s", (rule_id,))
    file_name = cur.fetchone()[0]
    if 'custom' not in file_name:
        return redirect(url_for('waf'))
    cur.execute("SELECT rule_id, description, variables, operators, actions FROM waf_rules WHERE rule_id = %s", (rule_id))
    rule = cur.fetchone()
    lines = rule[1].splitlines()
    comment = ["#" + line for line in lines]
    c_description = "\n".join(comment)
    variables = "|".join(loads(rule[2]))
    operators = '"' + rule[3] + '"'
    actions = ",\\\n    ".join(loads(rule[4]))
    pattern = f'{c_description}\nSecRule {variables} {operators} \\\n    "{actions}"\n\n'
    deleted = delete_waf_rule_from_file(f"/etc/nginx/modsec/app_rules/{app}_custom_modsec_rules.conf",pattern)
    if not deleted:
        return
    cur.execute("DELETE FROM waf_rules WHERE rule_id = %s", (rule_id))
    conn.commit()
    conn.close()

def update(target,rule_id, db_, res_):
    statement = ''
    if target == 'Action':
        statement = f'\nSecRuleUpdate{target}ById {rule_id} "{",".join(res_)}"\n'
        return statement
    for x, y in zip(db_, res_):
        if x != y:
            statement += f'\nSecRuleUpdate{target}ById {rule_id} "{x},{y}"\n'

    l = len(db_) - len(res_)
    if l > 0:
        for i in range(l):
            statement += f'\nSecRuleUpdate{target}ById {rule_id} "{db_[-i-1]},"\n'
    elif l < 0:
        for i in range(-l):
            statement += f'\nSecRuleUpdate{target}ById {rule_id} "{res_[len(db_)+i]}"\n'
    return statement

def update_waf_rule(app, rule_id, variables = None, actions = None):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT variables, actions FROM waf_rules WHERE rule_id = %s", (rule_id))
    rule = cur.fetchone()
    db_var, db_act = rule
    db_var = loads(db_var)
    db_act = loads(db_act)
        
    if variables:
        res_var = loads(variables)
#        res_var = "|".join(res_var)
        target = update('Target', rule_id, db_var, res_var)
        with open(f"/etc/nginx/modsec/app_rules/{app}_custom_modsec_rules.conf", 'a') as f:
            f.write(target)
        cur.execute("UPDATE waf_rules SET variables = %s WHERE rule_id = %s", 
                    (variables, rule_id))
    if actions:
        res_act = loads(actions)
        action = update('Action', rule_id, db_act, res_act)
        with open(f"/etc/nginx/modsec/app_rules/{app}_custom_modsec_rules.conf", 'a') as f:
            f.write(action)
        cur.execute("UPDATE waf_rules SET actions = %s WHERE rule_id = %s", 
                    (actions, rule_id))
    conn.commit()
    conn.close()

def toggle_waf_rule(app, rule_id, current_status):
    new_status = 'inactive' if current_status == 'active' else 'active'
    conn = get_connection()
    cur = conn.cursor()

    toggle = f'SecRuleRemoveById {rule_id}\n'
    if new_status == 'inactive':
        with open(f"/etc/nginx/modsec/app_rules/{app}_custom_modsec_rules.conf",'a') as f:
            f.write(toggle)

    elif new_status == 'active':
        with open(f"/etc/nginx/modsec/app_rules/{app}_custom_modsec_rules.conf",'r') as f:
            lines = f.readlines()
            for line in f:
                if str(rule_id) in line:
                    toggle = line
                    break

        with open(f"/etc/nginx/modsec/app_rules/{app}_custom_modsec_rules.conf",'w') as f:
            for line in lines:
                if toggle not in line:
                    f.write(line)
                    
    cur.execute("UPDATE waf_rules SET status = %s WHERE rule_id = %s", (new_status, rule_id))
    conn.commit()
    conn.close()

# Routes
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
            app.logger.info('Connexion réussie ✅') # à modifier
            return redirect(url_for('dashboard'))
        else:
            app.logger.error('Email ou mot de passe incorrect ❌') # à modifier

    return render_template('signin.html')

@app.route('/logout')
def logout():
    # Supprime toutes les données de session
    session.clear()
    app.logger.info("Déconnexion réussie 👋") # à modifier
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

@app.route('/waf', methods=['GET', 'POST'])
def waf():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nom FROM users WHERE email = %s", (email,))
    user_data = cur.fetchone()
    conn.close()
    nom = user_data[0] if user_data else ""

    # Filters from GET or POST
    selected_app = request.args.get("app") or request.form.get("app") 
    status_filter = request.args.get('status') or request.form.get('status')
    search_filter = request.args.get('search') or request.form.get('search')
    search_field = request.args.get('search_field') or request.form.get('search_field')
    page = int(request.args.get('page', 1))
    per_page = 15

    # Get app names
    apps = get_all_managed_apps()
    app_names = [row[0] for row in apps]

    if not selected_app and app_names:
        selected_app = app_names[0]

    filters = {}
    if selected_app:
        filters["selected_app"] = selected_app
    if status_filter:
        filters["status"] = status_filter
    if search_filter:
        filters['search'] = search_filter
    if search_field:
        filters['search_field'] = search_field

    # Handle form actions
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'add_rule':
            insert_waf_rule(
                selected_app,
                request.form.get('description'),
                request.form.get('variables'),
                request.form.get('operators'),
                request.form.get('actions')
            )
            if not waf_manager.reload_nginx():
                flash("Reload not accepted","error")
            #flash("Règle WAF ajoutée avec succès ✅", "success")
        elif form_type == 'delete_rule':
                delete_waf_rule(selected_app, request.form.get('rule_id'))
                if not waf_manager.reload_nginx():
                    flash("Reload not accepted","error")
            #flash("Règle WAF supprimée avec succès 🚫", "success")
        elif form_type == 'update_rule':
            update_waf_rule(
                selected_app,
                request.form.get('rule_id'),
                request.form.get('variables'),
                request.form.get('actions')
            )
            if not waf_manager.reload_nginx():
                flash("Reload not accepted","error")
            #flash("Règle WAF modifiée avec succès ✏", "success")
        elif form_type == 'toggle_status':
            toggle_waf_rule(
                selected_app,
                request.form.get('rule_id'),
                request.form.get('current_status')
            )
            if not waf_manager.reload_nginx():
                flash("Reload not accepted","error")
            #flash("Statut de la règle WAF modifié avec succès 🔄", "success")
        return redirect(url_for('waf',app=selected_app, page=page, status=status_filter, search=search_filter))

    rules, total_rules = get_all_waf_rules(page=page, per_page=per_page, filters=filters)
    total_pages = (total_rules + per_page - 1) // per_page

    return render_template('waf.html', nom=nom, rules=rules, apps=app_names, selected_app=selected_app, page=page, total_pages=total_pages, filters=filters)

@app.route('/apps', methods=['GET', 'POST'])
def apps():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nom FROM users WHERE email = %s", (email,))
    user_data = cur.fetchone()
    conn.close()
    nom = user_data[0] if user_data else ""

    if request.method == 'POST':
        form_type = request.form.get('form_type')
        
        if form_type == 'add_app':
            # Create new WebApp instance
            app_config = WebApp(
                name=request.form.get('name'),
                domain=request.form.get('domain'),
                backend_host=request.form.get('backend_host'),
                backend_port=int(request.form.get('backend_port')),
                ssl_enabled=request.form.get('ssl_enabled') == 'on',
#                custom_rules=request.form.get('custom_rules') or None,
                rate_limit=request.form.get('rate_limit') or None
            )
            
            if waf_manager.add_app(app_config):
                #flash(f"Application {app_config.name} ajoutée avec succès ✅", "success")
                # Reload nginx configuration
                if waf_manager.reload_nginx():
                    flash("Configuration Nginx rechargée avec succès 🔄", "success")
                    flash(f"Application {app_config.name} ajoutée avec succès ✅", "success")
                else:
                    waf_manager.remove_app(app_config.name)
                    flash("Erreur lors du rechargement de Nginx ⚠️. (Cause probable: application non existante)", "warning")
            else:
                flash(f"Erreur lors de l'ajout de l'application {app_config.name} ❌", "danger")
        
        elif form_type == 'remove_app':
            app_name = request.form.get('app_name')
            if waf_manager.remove_app(app_name):
                flash(f"Application {app_name} supprimée avec succès 🚫", "success")
                # Reload nginx configuration
                if waf_manager.reload_nginx():
                    flash("Configuration Nginx rechargée avec succès 🔄", "success")
                else:
                    flash("Erreur lors du rechargement de Nginx ⚠️", "warning")
            else:
                flash(f"Erreur lors de la suppression de l'application {app_name} ❌", "danger")
        
        return redirect(url_for('apps'))
    
    # GET request - display apps management page
    managed_apps = get_all_managed_apps()
    app_stats = get_app_stats()
    
    return render_template('apps.html', nom=nom, managed_apps=managed_apps, app_stats=app_stats)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
