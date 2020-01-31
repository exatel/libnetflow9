# libnetflow9

Netflow is a protocol which concisely describes a traffic information that
traversed a network router. libnetflow9 is a library for parsing packets
conforming to the Netflow9 format in order to extract meta information about the
traffic.

libnetflow9 is written in C++17, and has a compatible C API.

## Build


```console
mkdir build
cd build
cmake ..
make -j4
```
