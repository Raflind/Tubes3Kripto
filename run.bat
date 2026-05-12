docker build -f server/app/Dockerfile -t webchat .
docker run -d -p 3000:3000 webchat
