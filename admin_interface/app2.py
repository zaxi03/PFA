from flask import Flask, render_template, send_from_directory

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# Flask sert automatiquement tout ce qui est dans /static
# ex: /static/css/style.css → static/css/style.css

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
