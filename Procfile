web: uvicorn clamav_rest:app --host 0.0.0.0 --port $PORT --timeout-keep-alive 1000
worker: celery -A tasks:celery_app worker --loglevel=info --concurrency=4
postdeploy: alembic upgrade head
