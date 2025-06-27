#!/bin/bash
# Start Flask in background
gunicorn --bind 0.0.0.0:5001 receiver:app &

# Start NGINX in foreground (so Docker tracks it as main process)
nginx -g "daemon off;"
