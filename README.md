# libnetflow9 #

NetFlow is a protocol which concisely describes traffic information
that traversed a network router.  libnetflow9 is a library for decoding
packets conforming to the NetFlow9 format in order to extract meta
information about the traffic.

libnetflow9 is written in C++17, and has a compatible C API.

## Badges ##

### Building ###

![build workflow](https://github.com/doodeck/libnetflow9/actions/workflows/cmake.yml/badge.svg)

### Testing ###

![test workflow sys](https://github.com/doodeck/libnetflow9/actions/workflows/tests.yml/badge.svg)

![test workflow own](https://github.com/doodeck/libnetflow9/actions/workflows/tests-own.yml/badge.svg)


## Dependencies ##

Besides a C++17 compiler and CMake there are no additional
dependencies.

For building tests, you additionally need these libraries:

| dependency      | Debian package |
|-----------------|----------------|
| [googletest][1] | `libgtest-dev` |
| [libtins][2]    | `libtins-dev`  |

For benchmarks, you need [libbenchmark][3] (`libbenchmark-dev` in apt
repositories).

## Building with CMake ##

```console
mkdir build
cd build
cmake ..
make -j4
```

## Building on MacOS M1

```
mkdir build
cd build
cmake .. -DCMAKE_C_COMPILER=/opt/homebrew/bin/gcc-12 -DCMAKE_CXX_COMPILER=/opt/homebrew/bin/g++-12
cmake --build .
```

Otherwise it defaults to Clang toolset, which as of version:  

`Apple clang version 14.0.0 (clang-1400.0.29.202)`

is incapable of compiling the library. More details in the build log

https://github.com/doodeck/libnetflow9/actions/runs/4681045806/jobs/8293144058


## Building and running tests ##

```console
cmake .. -DNF9_BUILD_TESTS=ON
make -j4 netflowtests
./test/netflowtests
```

## Building examples ##

```console
cmake .. -DNF9_BUILD_EXAMPLES=ON
make -C examples/  -j 4
```


# Linking to the library #

To use the library in your program, you should include it as a
subdirectory in your CMake project, recurse into it, and then link
your executables with `netflow9` target.

# Examples #

The examples are located in `examples` directory:

- `examples/simple`

  This example program will listen for NetFlow packets on UDP port
  provided on the command line.  The example shows how you can use the
  library to inspect IPv4 flows:
  - Get the source and destination addresses
  - Get the number of bytes transferred

- `examples/stats`

  Like the simple example, this program listens for NetFlow packets on
  UDP port given on command line.  It demonstrates how you can extract
  statistics from the library, e.g. the number of cached data
  templates and memory usage.

# Usage #

## High level overview ##

1. Create an instance of the decoder: `nf9_init()`
2. Open a UDP socket and listen for NetFlow packets
3. Feed received packet to the decoder: `nf9_decode()`.  This returns an
   `nf9_packet`.
4. Inspect the packet - retrieve flow information, source
   address, destination address, bytes transferred etc.
5. Delete the packet (`nf9_free_packet()`) and go back to
   step #3.
6. Delete the state once you're done: `nf9_free()`.

## Details ##

### Library header ###

The library function prototypes are defined in `<netflow9.h>` header.

### Creating the decoder ###

NetFlow is a stateful protocol - in order to decode a packet you might
need to have some of the previous packets, which contain templates for
decoding.  You feed the library NetFlow packets, and it caches the
templates and keeps them in memory.  In libnetflow, the object that
holds these templates is called `nf9_state`, and it is created by the
function `nf9_init()`.

```c
nf9_state* state;
state = nf9_init(NF9_STORE_SAMPLING_RATES);
```

We passed `NF9_STORE_SAMPLING_RATES` as flags to `nf9_init` so we can
later retrieve the router sampling rates.

### Setting decoder options ###

Once the decoder is created, you can modify some of it's behavior,
e.g. for how long should decoded templates be considered valid.

Use `nf9_ctl` function to set decoder options:

```c
int nf9_ctl(nf9_state* state, int opt, long value);
```

The `opt` argument says which option to set, and `value` is the new
value.  `opt` should be one of the enumerations of enum `nf9_opt`.

For example, you can set memory limit of 4KB for allocated template
store with:

```c
nf9_ctl(state, NF9_OPT_MAX_MEM_USAGE, 4000);
```

### Receiving packets ###

Now the decoder is created and configured.  The library itself does not
deal with receiving the packets, you must do it yourself.

**NOTE**: For decoding packets, you must also provide the source
address of the sender, so use `recvfrom` and friends.

### Decoding the packet ###

Use `nf9_decode` to decode the received packet:

```c
uint8_t *packet_bytes;
size_t packet_size;
sockaddr_in peer;  /* packet sender */
nf9_packet *packet;

nf9_decode(state, &packet, packet_bytes, packet_size, &peer);
```

On success, `nf9_decode` returns 0 and writes pointer to heap-allocated
result to `*packet`.

### Retrieving information from a packet ###

#### NetFlow packet structure ####

In NetFlow9, every packet is divided into flowsets, and each flowset
is either a DATA flowset, DATA TEMPLATE flowset or an OPTIONS TEMPLATE
flowset.

As a user of this library, you're probably only ever interested in
DATA flowsets, which contain the actual traffic information, like
src/dst addresses and traffic volume.

The other flowset types are consumed by the library though.  Data
templates say how future DATA flowsets should be decoded, and OPTIONS
TEMPLATE flowsets contain static flow values that rarely change and
would take precious space if they were present in every DATA flowset.

#### Getting to data ####

With a decoded packet, we can iterate over the flowsets in it to find
DATA flowsets.

```c
unsigned num_flowsets, num_flows;
num_flowsets = nf9_get_num_flowsets(packet);

for (flowset = 0; flowset < num_flowsets; flowset++) {
    if (nf9_get_flowset_type(packet, flowset) != NF9_FLOWSET_DATA)
        continue;

    /* found the DATA flowset */
}
```

Ok, we found what we were looking for.

Every DATA flowset is further divided into "flows" which describe
traffic between specific hosts.  Iterate over them to get the details:

```c
num_flows = nf9_get_num_flows(packet, flowset);
for (flownum = 0; flownum < num_flows; flownum++) {
    /* do something with the flow [flowset, flownum] */
}
```

#### Extracting information from flows ####

Now we can get information about specific flows.  For example, we can
get source and destination addresses:

```c
struct in_addr src, dst;
size_t len;

len = sizeof(src);
if (nf9_get_field(packet, flowset, flownum, NF9_FIELD_IPV4_SRC_ADDR, &src, &len))
    /* source address is missing */
    continue;

len = sizeof(dst);
if (nf9_get_field(packet, flowset, flownum, NF9_FIELD_IPV4_DST_ADDR, &dst, &len))
    /* dest address is missing */
    continue;
```

To get the number of bytes:

```c
uint32_t in_bytes;

len = sizeof(in_bytes);
if (nf9_get_field(packet, flowset, flownum, NF9_FIELD_IN_BYTES, &in_bytes, &len))
    continue;

/* All NetFlow field values are in network byte order */
in_bytes = ntohl(in_bytes);
```

#### The sampling rate ####

The above is often not enough though, because for performance reasons
routers typically sample only part of the traffic (one out of every N
packets), and whatever is in `NF9_FIELD_IN_BYTES` field is just a
statistical sample of the whole traffic.

To get the approximate value of transferred bytes we can multiply
whatever is in `NF9_FIELD_IN_BYTES` by the router's sampling rate.

The sampling rate will typically not be present in the data flowset
though, but in option flowsets, which the library will cache.

To get the sampling rate, pass `NF9_STORE_SAMPLING_RATES` flag to
`nf9_init()`, and retrieve it with:

```c
uint32_t sampling;

nf9_get_sampling_rate(packet, flowset, flownum, &sampling, NULL);
```

And now to get the approximate value for the number of bytes
transferred:

```c
in_bytes *= sampling;
```

#### Extracting flow options ####

TODO

### Getting statistics from the decoder ###

TODO


[1]: https://github.com/google/googletest
[2]: https://github.com/mfontanini/libtins
[3]: https://github.com/google/benchmark
