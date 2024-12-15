Random Logo here

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

TODO: Add (CMake) building here

### Test

TODO: Generate a certificate and test

```bash
openssl req -x509 -newkey rsa:4096 -keyout localhost.key -out localhost.crt -sha256 -days 3650 -nodes -subj "/"

mv localhost.key test/share/cert/
mv localhost.crt test/share/cert/
```

## :bookmark: Cite US

Please cite us if this work is helpful to you.

```
@inproceedings{name,
  title={title},
  author={authors},
  booktitle={conference},
  year={2025}
}
```

## :bookmark: Acknowledgments

... Thanks for their great work!