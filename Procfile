web: uvicorn app:app --app-dir src --host 0.0.0.0 --port $PORT --timeout-keep-alive 1000
worker: PYTHONPATH=src python -m worker
