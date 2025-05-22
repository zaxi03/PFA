FROM nginx:1.27.5

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

# Revenir au répertoire NGINX par défaut
WORKDIR /etc/nginx

# Exposer le port standard
EXPOSE 80

# CMD reste celui de NGINX (pas besoin de le redéfinir)
