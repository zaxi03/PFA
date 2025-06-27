import os

def init_flask():
    file_path = '/etc/nginx/modsec/app_rules/flask_custom_modsec_rules.conf'
    os.makedirs(os.path.dirname(file_path), exist_ok=True)  # Create parent dirs
    open(file_path, 'a').close()

    rules_content = f"""
# Generated automatically

# Include base configuration
Include /etc/nginx/modsec/modsecurity.conf
Include /usr/local/modsecurity-crs/crs-setup.conf
Include /usr/local/modsecurity-crs/rules/*.conf
Include /etc/nginx/modsec/app_rules/flask_custom_modsec_rules.conf
"""
    file_path2 = '/etc/nginx/modsec/apps/flask.conf'
    os.makedirs(os.path.dirname(file_path2), exist_ok=True)
    with open('/etc/nginx/modsec/apps/flask.conf', 'w') as f:
        f.write(rules_content)

if __name__ == '__main__':
    init_flask()
