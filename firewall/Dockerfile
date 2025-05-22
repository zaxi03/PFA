FROM debian:bookworm

# Installer nftables, rsyslog, etc.
RUN apt update && \
    apt install -y nftables iproute2 iputils-ping curl net-tools rsyslog && \
    apt clean

# Fichier de règles (optionnel selon ton usage)
# COPY nftables.conf /etc/nftables.conf
COPY rsyslog-nftables.conf /etc/rsyslog.d/30-nftables.conf

# Script d’entrée
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]

