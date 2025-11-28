FROM python:alpine
WORKDIR /app
EXPOSE 8443

# Create user for the container
RUN adduser -D --uid 10001 python
RUN chown -R python:python /app

# Install trufflehog binary
RUN apk update && apk upgrade
RUN apk add curl
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
RUN trufflehog --version

# Install prerequisites
COPY requirements.txt .
RUN pip3 install --upgrade pip
RUN pip3 install --no-cache-dir -r requirements.txt

# Uninstall 
RUN pip3 uninstall -y pip
RUN rm -rf /root/.cache/pip
RUN apk -v cache clean
RUN apk --purge del curl apk-tools
RUN rm -f /bin/sh

COPY main.py .
COPY favicon.ico .

USER python

CMD ["gunicorn", "--certfile", "certs/server.crt", "--keyfile", "certs/server.key", "-k", "uvicorn.workers.UvicornWorker",  "--bind", "0.0.0.0:8443", "main:app"]