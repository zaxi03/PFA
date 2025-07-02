#!/bin/bash

echo "🚀 Entrypoint lancé"

while [ ! -f "/mnt/modsec-logs/modsec_audit.log" ]; do
  echo "🕓 Attente du fichier de log..."
  sleep 1
done

echo "✅ Fichier trouvé : lancement de logs_waf.py"
python logs_waf.py &

echo "🕓 Initialisation de la table waf_rules"
python populate_waf_rules.py &
 
echo "🚀 Démarrage de l’application Flask"
exec python app.py