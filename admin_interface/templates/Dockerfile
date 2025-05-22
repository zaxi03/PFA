# Étape 1 : Utiliser l'image de base NGINX
FROM nginx

# Étape 2 : Supprimer les fichiers HTML par défaut de NGINX
RUN rm -rf /usr/share/nginx/html/*

# Étape 3 : Exposer le port 80 (déjà utilisé par défaut par NGINX)
EXPOSE 80
