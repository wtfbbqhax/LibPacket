# Using www.github.com/wtfbbqhax/krakatoa
FROM arm64v8/krakatoa AS libpacket_dev_env

USER root
RUN apk update

VOLUME /volume/libpacket
WORKDIR /volume/libpacket

RUN apk add \
    libdaq-dev@local \
    libdaq-pcap-module@local \
    libdaq-dump-module@local

RUN apk add \
    build-base \
    cmake \
    ninja \
    gtest-dev

RUN echo alias vi=nvim > /root/.profile

RUN apk add neovim tmux ctags
