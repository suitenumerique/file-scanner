FROM python:3.11-slim

ENV PORT=8090
EXPOSE $PORT

WORKDIR /srv/clamav-rest
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["/bin/bash", "/srv/clamav-rest/run.sh"]
