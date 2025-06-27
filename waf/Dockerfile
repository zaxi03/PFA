FROM nginx:1.27.5

# Install Python and Flask (minimal setup)
RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Créer un environnement virtuel pour Python
RUN python3 -m venv /opt/venv

# Ajouter l’environnement virtuel au PATH
ENV PATH="/opt/venv/bin:$PATH"

# Installer les dépendances Python
RUN pip install --upgrade pip \
    && pip install flask gunicorn

# Dossier de travail temporaire
WORKDIR /config

# Copier le script local vers l'image
COPY config.sh .

# Rendre exécutable (au cas où)
RUN chmod +x config.sh

# Exécuter le script pendant le build
RUN ./config.sh

# Nettoyage si besoin
RUN rm -f config.sh


# Add Flask app
COPY receiver.py /app/

WORKDIR /app

COPY config/flask_init.py /app
RUN python3 flask_init.py
# Exposer le port standard
EXPOSE 80 5001

# Start both services in parallel (using a start script)
COPY start_services.sh /app/
RUN chmod +x /app/start_services.sh
CMD ["/app/start_services.sh"]
