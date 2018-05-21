docker stop mysql
docker rm mysql
docker run --name mysql -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=bbctest -e MYSQL_USER=user -e MYSQL_PASSWORD=pass -d -p 3306:3306 mysql
echo "** wait 12 seconds **"
sleep 12
#docker exec -it mysql /bin/bash
