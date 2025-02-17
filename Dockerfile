FROM ubuntu:jammy AS build

ENV GO111MODULE=on

RUN apt update

RUN apt install -y libpcap0.8 libpcap-dev golang ca-certificates build-essential 

RUN mkdir /output /src

ADD *.go go.* /src/

WORKDIR /src/

#RUN go build -ldflags "-L /usr/lib/x86_64-linux-gnu -linkmode external -extldflags -static" -o /output/iot-reflector

RUN go build -o /output/iot-reflector

FROM scratch

COPY --from=build /output/iot-reflector /iot-reflector

# FROM ubuntu:jammy

# RUN apt update && apt install -y libpcap0.8 && apt clean && rm -rf /var/cache/apt

# COPY --from=build /output/iot-reflector /iot-reflector

# ENTRYPOINT ["/iot-reflector"]