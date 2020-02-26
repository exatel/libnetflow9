# libnetflow9 #

Netflow is a protocol which concisely describes traffic information
that traversed a network router.  libnetflow9 is a library for parsing
packets conforming to the Netflow9 format in order to extract meta
information about the traffic.

libnetflow9 is written in C++17, and has a compatible C API.

# Building #

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

  This example program will listen for Netflow packets on UDP port
  provided on the command line.  The example shows how you can use the
  library to inspect IPv4 flows:
  - Get the source and destination addresses
  - Get the number of bytes transferred

- `examples/stats`

  Like the simple example, this program listens for Netflow packets on
  UDP port given on command line.  It demonstrates how you can extract
  statistics from the library, e.g. the number of cached data
  templates and memory usage.

# Usage #

## High level overview ##

1. Create an instance of the parser: `nf9_init()`
2. Open a UDP socket and listen for Netflow packets
3. Feed received packet to the parser: `nf9_parse()`.  This returns an
   `nf9_parse_result`.
4. Inspect the parse result - retrieve flow information, source
   address, destination address, bytes transferred etc.
5. Delete the parse result (`nf9_free_parse_result()`) and go back to
   step #3.
6. Delete the state once you're done: `nf9_free()`.

## Details ##

### Library header ###

The library function prototypes are defined in `<netflow9.h>` header.

### Creating the parser ###

Netflow is a stateful protocol - in order to decode a packet you might
need to have some of the previous packets, which contain templates for
decoding.  You feed the library Netflow packets, and it caches the
templates and keeps them in memory.  In libnetflow, the object that
holds these templates is called `nf9_state`, and it is created by the
function `nf9_init()`.

```c
nf9_state* state;
state = nf9_init(0);
```

### Setting parser options ###

Once the parser is created, you can modify some of it's behavior,
e.g. for how long should decoded templates be considered valid.

Use `nf9_ctl` function to set parser options:

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

Now the parser is created and configured.  The library itself does not
deal with receiving the packets, you must do it yourself.

**NOTE**: For parsing packets, you must also provide the source
address of the sender, so use `recvfrom` and friends.

### Parsing the packet ###

Use `nf9_parse` to decode the received packet:

```c
uint8_t *packet_bytes;
size_t packet_size;
sockaddr_in peer;  /* packet sender */
nf9_parse_result *parse_result;

nf9_parse(state, &parse_result, packet_bytes, packet_size, &peer);
```

On success, `nf9_parse` returns 0 and writes pointer to heap-allocated
result to `*parse_result`.

### Retrieving information from a parse result ###

#### Netflow packet structure ####

In Netflow9, every packet is divided into flowsets, and each flowset
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

With a parsed packet, we can iterate over the flowsets in it to find
DATA flowsets.

```c
unsigned num_flowsets, num_flows;
num_flowsets = nf9_get_num_flowsets(parse_result);

for (flowset = 0; flowset < num_flowsets; flowset++) {
    if (nf9_get_flowset_type(parse_result, flowset) != NF9_FLOWSET_DATA)
        continue;

    /* found the DATA flowset */
}
```

Ok, we found what we were looking for.

Every DATA flowset is further divided into "flows" which describe
traffic between specific hosts.  Iterate over them to get the details:

```c
num_flows = nf9_get_num_flows(parse_result, flowset);
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
if (nf9_get_field(parse_result, flowset, flownum, NF9_FIELD_IPV4_SRC_ADDR, &src, &len))
    /* source address is missing */
    continue;

len = sizeof(dst);
if (nf9_get_field(parse_result, flowset, flownum, NF9_FIELD_IPV4_DST_ADDR, &dst, &len))
    /* dest address is missing */
    continue;
```

To get the number of bytes:

```c
uint32_t in_bytes;

len = sizeof(in_bytes);
if (nf9_get_field(parse_result, flowset, flownum, NF9_FIELD_IN_BYTES, &in_bytes, &len))
    continue;

/* All Netflow field values are in network byte order */
in_bytes = ntohl(in_bytes);
```

#### Extracting flow options ####

The above is often not enough though, because for performance reasons
routers typically sample only part of the traffic (one out of every N
packets), and whatever is in `NF9_FIELD_IN_BYTES` field is just a
statistical sample of the whole traffic.

To get the approximate value of transferred bytes we can multiply
whatever is in `NF9_FIELD_IN_BYTES` by the router's sampling rate.

The sampling rate will typically not be present in the data flowset
though, but in option flowsets, which the library will cache.

To access the cache and retrieve the sampling rate, use
`nf9_get_option`:

```c
uint32_t sampling;

len = sizeof(sampling);
if (!nf9_get_option(parse_result, NF9_FIELD_FLOW_SAMPLER_RANDOM_INTERVAL, &sampling, &len))
    sampling = ntohl(sampling);
else
    sampling = 1;
```

And now to get the approximate value for the number of bytes
transferred:

```c
in_bytes *= sampling;
```

### Getting statistics from the parser ###

TODO


[1]: https://github.com/google/googletest
[2]: https://github.com/mfontanini/libtins
[3]: https://github.com/google/benchmark
