migrate:
	docker-compose -f docker-compose.dev.yml run --rm migrate

resetdb:
	docker-compose -f docker-compose.dev.yml run --rm resetdb

up:
	docker-compose -f docker-compose.dev.yml up --build

down:
	docker-compose -f docker-compose.dev.yml down