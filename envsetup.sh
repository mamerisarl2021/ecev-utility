#!/bin/bash

if [ -d "env" ] 
then
    echo "Python virtual environment exists." 
else   
    virtualenv -p python3 venv
fi

# source venv/bin/activate
# pip3 install -r requirements.txt
# cd app
# python3 manage.py makemigrations
# python3 manage.py migrate
# sudo python3 manage.py createsuperuser

if [ -d "logs" ] 
then
    echo "Log folder exists." 
else
    mkdir logs
    touch logs/error.log logs/access.log
fi

sudo chmod -R 777 logs