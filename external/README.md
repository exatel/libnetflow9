# external libraries sources directory

## Working with submodules

https://git-scm.com/book/en/v2/Git-Tools-Submodules

## Used Libraries

### libtins
https://github.com/mfontanini/libtins.git / git@github.com:doodeck/libtins.git

### quick and dirty notes regarding building external dependencies

#### (AWS Linux 2)
```
sudo yum install libpcap-devel openssl-devel cmake
mkdir build && cd build
cmake3 ../ -DLIBTINS_ENABLE_CXX11=1
cmake3 --build .
```

#### Ubuntu on GH Codespace
```
git submodule init && git submodule update
sudo apt update
sudo apt-get install -y libpcap-dev
sudo apt-get install -y googletest # ???
cd external/libtins
mkdir build && cd build
git submodule init && git submodule update # to pull libnetflow9/external/libtins/googletest
cmake ..  -DLIBTINS_ENABLE_CXX11=1
cmake --build .
# Now tests
# sudo apt-get install libpthread-workqueue-dev
# sudo apt-get install libpthread-workqueue0
# sudo apt-get install libpthread-stubs0-dev
cd ../../build
cmake .. -DNF9_BUILD_TESTS=ON
cmake --build .
./test/netflowtests
```
