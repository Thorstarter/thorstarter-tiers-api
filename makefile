dev:
	@which reflex>/dev/null || go install github.com/cespare/reflex@latest
	reflex -s -d none -r '(src/.*\.go$$)' -- go run *.go

run:
	go run *.go

build:
	go build -o tiersapi .

db:
	psql ts_tiers_api

dbuser:
	psql -c "create role admin with login superuser password 'admin';"

dbcreate:
	psql -c "create database ts_tiers_api with owner admin;"
	psql ts_tiers_api < db.sql

dbreset:
	psql -c "drop database ts_tiers_api;"
	psql -c "create database ts_tiers_api with owner admin;"
	psql ts_tiers_api < db.sql
