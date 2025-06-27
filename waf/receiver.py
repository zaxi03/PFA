from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/trigger', methods=['POST'])
def handle_trigger():
    code = request.json.get("code")
#    return jsonify({"status":"working"}), 200, {"Content-Type": "application/json"}
    try:
        if code == 1:
            # Test configuration first
            result = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
            if result.returncode != 0:
                return jsonify({"status": f"Nginx config test failed: {result.stderr}"}), 250
                #return jsonify({"status": "OK"}), 250
            return jsonify({"status": f"{result}"})

        elif code == 2:
            # Reload nginx
            result = subprocess.run(['nginx', '-s', 'reload'], capture_output=True, text=True)
            if result.returncode != 0:
                return jsonify({"status": f"Nginx reload failed: {result.stderr}"}), 250

            return jsonify({"status": "Nginx reloaded successfully"}, {"message": f"{result}"})
        else:
            return jsonify({"status": "Invalid code"}), 400

    except Exception as e:
        return jsonify({"status": f"Error reloading nginx: {e}"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
