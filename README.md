# PreAcher: Secure and Practical Password Pre-Authentication by Content Delivery Networks


## :bookmark: Introductory info here

## :bookmark: Getting started

### Install dependencies

```bash
sudo apt-get update
sudo apt-get install git gcc g++ cmake libsodium-dev libssl-dev -y
sudo apt-get install pkg-config libworkflow-dev -y
```

### Build

```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make
```

`libPreAcher.a` is generated in the `build` directory.

### Test

There is an RSA private key at `test/server.pem`, this key is used for encrypting the password. The corresponding public key is embedded at
`test/share/static/js/single_client.js::EncryptNonceBase64`.

Before running the test, you need to generate the certificate and key files for the HTTPS server. Ideally, you should use a valid certificate signed by a trusted certificate authority. However, for
testing purposes, you can generate a self-signed certificate using the following command:

```bash
openssl req -x509 -newkey rsa:4096 -keyout localhost.key -out localhost.crt -sha256 -days 3650 -nodes -subj "/"

mv localhost.key test/share/cert/
mv localhost.crt test/share/cert/
```

The test executable can be built by running the following command:

```bash
cd build
make cdn server hash-cdn hash-server
```

They will be generated in the `build/test` directory.

Run the server:

```bash
cd build/test
# For PreAcher
./cdn&
./server&
# For DuoHash
./hash-cdn&
./hash-server&
```

Visit the website at `https://localhost:8000/` and test the system.

## :bookmark: Cite US

Please cite us if this work is helpful to you.

```
@inproceedings{DBLP:conf/nsdi/preacher,
  author       = {Lin, Shihan and Chen, Suting and Xiao, Yunming and Gu, Yanqi and Kuzmanovic, Aleksandar and Yang, Xiaowei},
  title        = {PreAcher: Secure and Practical Password Pre-Authentication by Content Delivery Networks},
  booktitle    = {22nd {USENIX} Symposium on Networked Systems Design and Implementation,
                  {NSDI} 2025, Philadelphia, PA, April 28-30, 2025},
  publisher    = {{USENIX} Association},
  year         = {2025}
}
```

## :bookmark: Acknowledgments

... Thanks for their great work!
