#!/bin/bash
#SERVICES=('celeryd' 'celerybeat')
SERVICES=('celery')
  
for service in ${SERVICES[@]}; do
    if ps ax | grep -v grep | grep $service > /dev/null
    then
        echo "$service service running, everything is fine" >/dev/null
    else
        echo "$service is not running"
        cd /home/votacao/helios-server    
         

        if [ "$service" == "celery" ]; then
	    /usr/local/bin/celery -A helios worker -l info --concurrency=5 -f celery.log &
        else
            python manage.py $service --logleve=INFO -f $service.log &
        fi

        echo "$service is not running!" | mail -s "$service down" root
    fi
done
exit 0
