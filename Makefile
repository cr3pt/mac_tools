.PHONY: deploy test clean
deploy:
	./deploy.sh
test:
	docker-compose exec api pytest
clean:
	docker-compose down -v && docker volume prune -f
