# Utilise une image Python légère
FROM python

# Définir le répertoire de travail
WORKDIR /app

# Installer les dépendances système nécessaires pour mysqlclient
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copier le fichier requirements.txt et installer les packages Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copier le reste de l'application Flask
COPY . .

# Exposer le port Flask
EXPOSE 5000

# Commande pour démarrer l'app Flask
CMD ["/entrypoint.sh"]

