from flask import Flask, request, jsonify
import subprocess
import re
import ipaddress

app = Flask(__name__)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def build_nft_command(rule):
    action = rule.get("action", "accept")
    protocol = rule.get("protocol", "tcp")
    port = rule.get("port")
    src = rule.get("source_ip", "0.0.0.0/0")
    dest = rule.get("destination_ip", "0.0.0.0/0")

    if not port:
        return None

    cmd = [
        "nft", "add", "rule", "inet", "filter", "input",
        "ip", "saddr", src,
        "ip", "daddr", dest,
        protocol, "dport", str(port),
        action
    ]
    return cmd

@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    rule = request.get_json()
    action = rule.get("action", "accept")
    protocol = rule.get("protocol", "tcp")
    port = rule.get("port")
    src = rule.get("source_ip", "0.0.0.0/0")
    dest = rule.get("destination_ip", "0.0.0.0/0")

    try:
        # 1. Lister les règles avec handles
        result = subprocess.run(
            ["nft", "--handle", "list", "chain", "inet", "filter", "input"],
            capture_output=True,
            text=True,
            check=True
        )
        rules = result.stdout.splitlines()

        # 2. Rechercher la règle DROP correspondant à l'IP
        handle = None
        for line in rules:
            if f"ip saddr {src} ip daddr {dest} {protocol} dport {str(port)} {action}" in line:
                match = re.search(r'handle (\d+)', line)
                if match:
                    handle = match.group(1)
                    break


        # 3. Supprimer la règle via son handle
        subprocess.run(
            ["nft", "delete", "rule", "inet", "filter", "input", "handle", handle],
            check=True
        )
        with open("/etc/nftables.conf", "w") as f:
            subprocess.run(["nft", "list", "ruleset"], stdout=f, stderr=subprocess.DEVNULL, check=True)
        return jsonify({"message": "Régle supprimée avec succès"}), 200

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Erreur système : {e.stderr or str(e)}"}), 500

@app.route('/add_rule', methods=['POST'])
def add_rule():
    rule = request.json
    cmd = build_nft_command(rule)

    if not cmd:
        return jsonify({"error": "Règle invalide"}), 400

    try:
        subprocess.run(cmd, check=True)
        with open("/etc/nftables.conf", "w") as f:
            subprocess.run(["nft", "list", "ruleset"], stdout=f, stderr=subprocess.DEVNULL, check=True)
        return jsonify({"status": "Règle ajoutée avec succès"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/rules', methods=['GET'])
def list_rules():
    result = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
    return jsonify({"rules": result.stdout})

@app.route('/block_ip', methods=['POST'])
def block_ip():
    data = request.get_json()
    ip = data.get('ip')

    if not ip:
        return jsonify({"error": "Champ 'ip' requis"}), 400

    if not is_valid_ip(ip):
        return jsonify({"error": "Adresse IP invalide"}), 400

    cmd = [
        "nft", "add", "rule", "inet", "filter", "input",
        "ip", "saddr", ip,
        "drop"
    ]

    try:
        # Ajout de la règle dans nftables
        subprocess.run(cmd, check=True)

        # Sauvegarde des règles dans /etc/nftables.conf
        with open("/etc/nftables.conf", "w") as f:
            subprocess.run(["nft", "list", "ruleset"], stdout=f, stderr=subprocess.DEVNULL, check=True)

        return jsonify({"message": f"Adresse IP {ip} bloquée avec succès"}), 200

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Erreur lors de l'ajout de la règle : {e.stderr or str(e)}"}), 500

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    data = request.get_json()
    ip = data.get('ip')

    if not ip:
        return jsonify({"error": "Champ 'ip' requis"}), 400

    try:
        # 1. Lister les règles avec handles
        result = subprocess.run(
            ["nft", "--handle", "list", "chain", "inet", "filter", "input"],
            capture_output=True,
            text=True,
            check=True
        )
        rules = result.stdout.splitlines()

        # 2. Rechercher la règle DROP correspondant à l'IP
        handle = None
        for line in rules:
            if f"ip saddr {ip}" in line and "drop" in line:
                match = re.search(r'handle (\d+)', line)
                if match:
                    handle = match.group(1)
                    break

        if not handle:
            return jsonify({"error": f"Aucune règle DROP trouvée pour {ip}"}), 404

        # 3. Supprimer la règle via son handle
        subprocess.run(
            ["nft", "delete", "rule", "inet", "filter", "input", "handle", handle],
            check=True
        )
        with open("/etc/nftables.conf", "w") as f:
            subprocess.run(["nft", "list", "ruleset"], stdout=f, stderr=subprocess.DEVNULL, check=True)
        return jsonify({"message": f"Adresse IP {ip} débloquée avec succès"}), 200

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Erreur système : {e.stderr or str(e)}"}), 500

if __name__ == '__main__':
    # Initialisation de la table et chaîne si elle n'existe pas encore
    subprocess.run(["nft", "add", "table", "inet", "filter"])
    subprocess.run([
        "nft", "add", "chain", "inet", "filter", "input",
        "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"
    ])
    subprocess.run(["nft", "add", "table", "ip", "filter"], stderr=subprocess.DEVNULL)
    subprocess.run([
        "nft", "add", "chain", "ip", "filter", "forward",
        "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "accept", ";", "}"
    ], stderr=subprocess.DEVNULL)

    app.run(debug=True, host='0.0.0.0', port=9000)
