#!/bin/bash

USER="root"
PASS="root"
DB="flask_db"
TABLE="waf_logs"
ARCHIVE_PATH="/mnt/modsec-logs/archive/modsec_logs.sql.gz"
CUTOFF_DATE=$(date -d '7 days ago' +%F)

mysql -u"$USER" -p"$PASS" "$DB" -e "DELETE FROM $TABLE WHERE timestamp < '${CUTOFF_DATE} 00:00:00';"

if [ $? -eq 0 ]; then
    echo "$(date): Deleted old DB entries before $CUTOFF_DATE"
else
    echo "$(date): Failed to delete old DB entries"
fi
