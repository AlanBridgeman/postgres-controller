FROM python:3.12.7-alpine3.20

COPY requirements.txt /

RUN apk --update add postgresql-dev \
  && apk --update add --virtual build-dependencies gcc libffi-dev musl-dev \
  && pip install -r requirements.txt \
  && apk del build-dependencies

COPY controller.py functions.py /

CMD ["python", "-u", "controller.py"]
