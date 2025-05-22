#!/bin/bash

# Démarrer rsyslog en foreground
rsyslogd

# Appliquer les règles nftables
if [ -f /etc/nftables.conf ]; then
    echo "[INFO] Applying nftables rules"
    nft -f /etc/nftables.conf
else
    echo "[WARN] /etc/nftables.conf not found"
fi

# Suivre les logs en temps réel
tail -F /var/log/nftables.log
