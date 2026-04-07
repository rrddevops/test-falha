FROM node:18-bullseye-slim

WORKDIR /app

COPY package.json tsconfig.json ./
RUN npm install

COPY src ./src
COPY uploads ./uploads
COPY data ./data

RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]