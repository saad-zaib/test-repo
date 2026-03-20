FROM node:18-slim
WORKDIR /app
RUN apt-get update && apt-get install -y iputils-ping
RUN echo "CTF{test}" > /flag.txt
COPY package.json .
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]