# external libraries sources directory

## Working with submodules

https://git-scm.com/book/en/v2/Git-Tools-Submodules

## Used Libraries

### libtins
https://github.com/mfontanini/libtins.git / git@github.com:doodeck/libtins.git

#### building
##### (AWS Linux 2)
```
sudo yum install libpcap-devel openssl-devel cmake
mkdir build && cd build
cmake3 ../ -DLIBTINS_ENABLE_CXX11=1
cmake3 --build .
```

##### Ubuntu on GH Codespace
```
git submodule init && git submodule update
sudo apt update
sudo apt-get install -y libpcap-dev
sudo apt-get install -y googletest # ???
# libpthread-workqueue-dev
cd external/libtins
mkdir build && cd build
git submodule init && git submodule update # to pull libnetflow9/external/libtins/googletest
cmake ..  -DLIBTINS_ENABLE_CXX11=1
cmake --build .
```

### googletest
