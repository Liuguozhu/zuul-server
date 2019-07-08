#!/bin/sh
#nohup java -server -Xmx64m -jar zuul-server.jar &
echo "nohup java -jar -Djava.security.egd=file:/dev/./urandom zuul-server.jar &"
. /etc/profile
nohup java -jar -Djava.security.egd=file:/dev/./urandom zuul-server.jar --spring.profiles.active=prod > log.file 2>&1 &
