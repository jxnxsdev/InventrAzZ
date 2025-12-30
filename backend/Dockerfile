FROM node:latest

RUN mkdir -p /usr/src/stagestream_backend
WORKDIR /usr/src/stagestream_backend

COPY package.json /usr/src/stagestream_backend
RUN apt-get update
RUN apt-get install -y build-essential
RUN npm install --build-from-source

RUN npm install -g typescript

COPY . /usr/src/stagestream_backend

RUN tsc

CMD ["node", "build/index.js"]