#!/bin/bash

# pip install --upgrade virtualenv

sudo rm -rf /usr/src/ecev-utility/venv

virtualenv -p python3 venv

sudo chmod -R 777 venv
sudo chmod -R 777 /usr/src/ecev-utility/app/PDFs
sudo chmod -R 777 /usr/src/ecev-utility/app/CEVs

source /usr/src/ecev-utility/venv/bin/activate


pip3 install -r requirements.txt

pip3 install django

cd /usr/src/ecev-utility/app 

echo "from django.contrib.auth.models import User; User.objects.filter(email='gdjamal@mameribj.com').delete(); User.objects.create_superuser('mameri', 'gdjamal@mameribj.com', 'R00t#123E')" | python3 manage.py shell
# python3 DJANGO_SUPERUSER_PASSWORD=ammin ./manage.py createsuperuser --noinput --username mamerisarl --email gdjamal@mameribj.com > password.txt

# python3 manage.py makemigrations

# python3 manage.py migrate

chown ubuntu:ubuntu db.sqlite3

python3 manage.py collectstatic --noinput

sudo cp -rf ../gunicorn.service /etc/systemd/system/

sudo systemctl daemon-reload

sudo systemctl start gunicorn

echo "Gunicorn has started."

sudo systemctl enable gunicorn

echo "Gunicorn has been enabled."

sudo systemctl status gunicorn

sudo systemctl restart gunicorn