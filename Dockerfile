FROM python:alpine
WORKDIR /app
EXPOSE 5000

RUN adduser -D --uid 10001 python
RUN chown -R python:python /app

COPY requirements.txt .
RUN pip3 install --upgrade pip
RUN pip3 install --no-cache-dir -r requirements.txt

RUN pip3 uninstall -y pip
RUN rm -rf /root/.cache/pip
RUN apk update && apk upgrade
RUN apk -v cache clean
RUN apk --purge del apk-tools
RUN rm -f /bin/sh

COPY main.py .

USER python

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "main:app"]