FROM alpine:3.19

ARG LUA_VERSION=5.2
ARG LUA_MODULES="luaffi lunit luacheck luacov luacov-html"
ARG LUA_ROCKS_SERVER="https://luarocks.org/dev"

RUN apk add --no-cache \
        bash \
        luajit \
        lua${LUA_VERSION} \
        lua${LUA_VERSION}-bit32 \
    \
    && apk add --no-cache --virtual .build-deps \
        build-base \
        git \
        openssl-dev \
        lua${LUA_VERSION}-dev \
        luarocks${LUA_VERSION} \
    \
    && ln -s /usr/bin/lua${LUA_VERSION} /usr/local/bin/lua \
    \
    && for rock in ${LUA_MODULES}; do \
        luarocks-${LUA_VERSION} install --server=${LUA_ROCKS_SERVER} ${rock}; \
       done \
    \
    && apk del .build-deps

ADD https://github.com/philips/lualint/raw/master/lualint /bin/lualint
RUN chmod +x /bin/lualint \
    && \
    ln -s /usr/bin/luac${LUA_VERSION} /usr/bin/luac \
    && \
    ln -s /usr/local/share/lua/5.2 /usr/local/share/lua/5.1

RUN mkdir -p /github/workspace
VOLUME ["/github/workspace"]

WORKDIR "/github/workspace"
