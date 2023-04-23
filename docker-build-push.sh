#!/usr/bin/bash
cd Client/
echo $1
docker build . -t clientkuber:$1
docker tag clientkuber:$1 mzahid22/clientkuber:$1
docker push mzahid22/clientkuber:$1

cd ../Server/
echo $2
docker build . -t serverkuber:$2
docker tag serverkuber:$2 mzahid22/serverkuber:$2
docker push mzahid22/serverkuber:$2


