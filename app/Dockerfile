FROM image-registry.overlord.se/mirror/ubi9/nodejs-22-minimal:latest

WORKDIR /opt/app-root/src

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

USER 1001

EXPOSE 3000

CMD ["node", "server.js"]
