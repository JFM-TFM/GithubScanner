FROM python:alpine
WORKDIR /app
EXPOSE 8443
ENV PYTHONUNBUFFERED=1

# Create user for the container
RUN adduser -D --uid 10001 python
RUN chown -R python:python /app

# Upgrade packages
RUN apk update && apk upgrade

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