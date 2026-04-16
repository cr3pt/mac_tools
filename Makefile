.PHONY: deploy dev migrate test clean
deploy:
	./deploy.sh
dev:
	uvicorn noriben_soc.api.main:app --reload --host 0.0.0.0
migrate:
	alembic upgrade head
test:
	pytest tests/ -v
clean:
	docker-compose down -v && docker volume prune -f