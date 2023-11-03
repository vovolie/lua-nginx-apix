FROM openresty/openresty:1.21.4.1-1-alpine-fat
ENV REFRESHED_AT 2022-06-14

RUN apk --no-cache add ca-certificates tzdata \
    && \cp -a /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && apk del tzdata ca-certificates \
    && rm -rf /var/cache/apk/*

RUN /usr/local/openresty/luajit/bin/luarocks install xxtea
RUN opm install knyar/nginx-lua-prometheus
RUN opm install openresty/lua-resty-limit-traffic