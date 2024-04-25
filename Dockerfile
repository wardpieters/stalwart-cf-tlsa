# pull the image from docker hub
FROM python:3.10-alpine

# adds metadata to an image
LABEL MAINTAINER="Ward Pieters <mail@ward.nl>"
LABEL version="1.0"

# copy the requirements file into the image
COPY ./requirements.txt /src/requirements.txt

# switch working directory
WORKDIR /src

# install the dependencies and packages in the requirements file
RUN pip install -r requirements.txt

# copy every content from the local file to the image
COPY ./src /src

# configure the container to run in an executed manner
ENTRYPOINT ["python"]

CMD ["main.py"]