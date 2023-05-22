# Certificate Service

A simple example to demonstrate reading a SSL certificate, private key and using it to sign a payload.

## How to build
```sh
 $ mkdir build
 $ cd build
 $ clear && cmake .. && make
```

## How to run

```
#create a private key file using ssh at /tmp/private.key location
# and run the following command
./key_reader
```