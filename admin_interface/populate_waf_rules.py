import os
import re
from json import dumps
from glob import glob
import MySQLdb

def get_logical_lines(lines):
    logical_line = ""
    for line in lines:
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            logical_line += stripped[:-1]
        else:
            logical_line += stripped
            yield logical_line.strip()
            logical_line = ""

def parse_modsec_rule_file(file_path):
    rules = []
    # Check if the file exists
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            physical_lines = f.readlines()
        
        commented_lines = []
        current_comment = []

        for line in get_logical_lines(physical_lines):
            stripped_line = line.strip()
            # Match lines that define ModSecurity rules
            rule_match = re.match(r'SecRule\s+([^\s]+)\s+"([^"]+)"\s+"id:(\d+),\s+(.*)"', stripped_line)
            if rule_match:
                rule_variables = rule_match.group(1)  # The first group is the pattern
                variables = dumps(rule_variables.split("|"))
                operators = rule_match.group(2)     # The fourth group is the message
                rule_id = rule_match.group(3)      # The third group is the rule id
                rule_actions = rule_match.group(4)
                actions = dumps(re.split(r',\s+', rule_actions))
                rule_description = commented_lines or current_comment
                description = "\n".join(rule_description)
                origin_file, _ = os.path.splitext(file_path)
                rules.append({
                    'rule_id': rule_id,
                    'variables': variables,
                    'operators': operators,
                    'actions': actions,
                    'description': description,
                    'status': 'active',
                    'origin_file': origin_file
                })

            elif stripped_line.startswith('#'):
                commented_lines.append(stripped_line.lstrip('#'))

            elif stripped_line == '' and commented_lines:
                current_comment = commented_lines.copy()
                commented_lines = []
    return rules

def get_connection():
    return MySQLdb.connect(
        host="db",
        user="root",
        password="root",
        database="flask_db"
    )

def populate_waf_rules_from_modsec():
    modsec_files = [
        "/etc/nginx/modsec/modsecurity.conf",
        "/usr/local/modsecurity-crs/crs-setup.conf",
        "/usr/local/modsecurity-crs/rules/*.conf"
    ]
    
    all_rules = []
    for file_path in modsec_files:
        # If the path contains a wildcard (e.g., "rules/*.conf"), expand it
        if '*' in file_path:
            file_paths = glob(file_path)  # Glob will expand the wildcard
        else:
            file_paths = [file_path]
        
        for file in file_paths:
            if file.endswith('.conf'):
                all_rules.extend(parse_modsec_rule_file(file))
    
    # Now we need to insert these rules into the database
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT COUNT(*) FROM waf_rules")
    count = cur.fetchone()[0]

    if count == 0:
        for rule in all_rules:
            # Check if the rule already exists in the database
            cur.execute("SELECT COUNT(*) FROM waf_rules WHERE rule_id = %s", (rule['rule_id'],))
            if cur.fetchone()[0] == 0:  # If the rule doesn't exist, insert it
                cur.execute("INSERT INTO waf_rules (rule_id, description, variables, operators, actions, status, origin_file) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
                            (rule['rule_id'], rule['description'], rule['variables'], rule['operators'], rule['actions'], rule['status'], rule['origin_file']))
                conn.commit()
        print("Table waf_rules remplie avec succès ✅")
    else:
        print("La table waf_rules contient déjà des données — population ignorée ✅")
    conn.close()

if __name__ == '__main__':
    populate_waf_rules_from_modsec()
