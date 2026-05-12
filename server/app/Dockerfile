FROM oven/bun:1

WORKDIR /app

COPY server/app/package.json .
COPY server/app/bun.lock ./

RUN bun install

COPY server/app/ .

COPY client/ /client/

CMD ["bun", "run", "src/index.ts"]