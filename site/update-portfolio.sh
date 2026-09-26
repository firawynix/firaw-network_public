#!/bin/sh
set -eu
cd /home/ksdev/firawynix-portfolio
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --data-only --column-inserts -t system_settings -t projects' > "/home/ksdev/ipscan-site/portfolio-before-network-$(date -u +%Y%m%dT%H%M%SZ).sql"
docker cp backend/migrations/87_firaw_network.sql firawynix-postgres:/tmp/87_firaw_network.sql
docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /tmp/87_firaw_network.sql'
docker compose build frontend
docker compose up -d --no-deps frontend
