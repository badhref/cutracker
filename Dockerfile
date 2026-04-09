FROM node:24-slim

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

# Persistent volume should be mounted at /app/data
# The DB_PATH env var lets you redirect the database there
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "--experimental-sqlite", "server.js"]
