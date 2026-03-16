FROM node:18

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y apt-utils build-essential

WORKDIR /app
COPY package.json .
RUN npm install
COPY package.json .
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "app.js"]