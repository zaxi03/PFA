FROM debian:stable-slim

# Installation des dépendances nécessaires
RUN apt-get update && apt-get install -y \
    iproute2 \
    nftables \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    rsyslog \
    && apt-get clean

# Créer un environnement virtuel pour Python
RUN python3 -m venv /opt/venv

# Ajouter l’environnement virtuel au PATH
ENV PATH="/opt/venv/bin:$PATH"

# Copier les fichiers de configuration et de l'application
COPY config/nftables.conf /etc/nftables.conf
COPY app /app
WORKDIR /app

# Installer les dépendances Python
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Appliquer les règles nftables puis démarrer l'application Flask
CMD ["sh", "-c", "nft -f /etc/nftables.conf && python firewall_api.py && service rsyslog start"]
