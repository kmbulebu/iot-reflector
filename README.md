# iot-reflector

## About this project

iot-reflector allows mDNS/Bonjour devices such as printers, Chromecasts or Spotify Connect speakers, discoverable and usable by other devices located on different networks.

## How it works

Iot-reflector works by intercepting all mDNS traffic on one interface and re-sends them on one or more other network interfaces.

The mDNS packets are modified before reflection:
- Questions that contain IPv6 link local addresses in them are removed.
- IPv6 link local answers are removed.
- NSEC answers are removed.

# Debugging & Profiling

If developing on MacOS, first install Wireshark to setup your user with the ability to use libpcap.

A pprof server will listen on port `6060` if the you use the `-debug` flag.

More information on pprof is available [here](https://golang.org/pkg/net/http/pprof/)

## Attribution

This project is a derivative of the [bonjour-reflector project](https://github.com/Gandem/bonjour-reflector). 

## License

MIT
