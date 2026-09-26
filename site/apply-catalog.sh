#!/bin/sh
set -eu
cd /home/ksdev/firawynix-portfolio
docker cp /home/ksdev/ipscan-site/catalog.sql firawynix-postgres:/tmp/ipscan-catalog.sql
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --data-only --column-inserts -t projects -t games -t system_settings' > "/home/ksdev/ipscan-site/catalog-before-ipscan-$(date -u +%Y%m%dT%H%M%SZ).sql"
docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /tmp/ipscan-catalog.sql'
