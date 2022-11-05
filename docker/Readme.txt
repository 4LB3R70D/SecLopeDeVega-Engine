# https://docs.docker.com/language/golang/build-images/

# Use this from the 'engine' folder
docker build -t [YOUR_TAG] -f docker/Dockerfile .

or 

# from git repository
docker build -t [YOUR_TAG] -f docker/Dockerfile .