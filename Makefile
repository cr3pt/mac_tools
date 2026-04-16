
sync-rules:
	python3 addons/sync_sigmahq.py

migrate:
	cd noriben_soc && alembic upgrade head

ui:
	cp browser_ui/* noriben_soc/

dev:
	make sync-rules migrate ui && docker-compose up
