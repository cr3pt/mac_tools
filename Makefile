.PHONY: deploy test clean
deploy:
	bash deploy.sh
test:
	docker compose exec api pytest tests/ -v
clean:
	docker compose down -v && docker volume prune -f
