FROM node:alpine as base

FROM certbot/dns-cloudflare

RUN apk update && apk add curl libstdc++ g++ gcc libgcc linux-headers

# copy over node binary
ENV NODE_PATH="/usr/local/bin/node"
COPY --from=base /usr/local/lib/node_modules/ /usr/local/lib/node_modules/
COPY --from=base /usr/local/bin/node /usr/local/bin/
RUN node /usr/local/lib/node_modules/npm/bin/npm-cli.js install -g npm

# rest of image

WORKDIR /app

COPY src package.json package-lock.json tsconfig.json /app/

RUN npm install --no-optional && npm run build

ENTRYPOINT [ "node", "built/index" ]
