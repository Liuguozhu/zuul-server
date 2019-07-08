ps -ef | grep zuul-server.jar | grep -v grep | cut -c 9-15 | xargs kill -s 9
