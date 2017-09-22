# Info

cert-master manages certificates in a central system. 

> IMPORTANT: Software is in an alpha state!

Currently certificates can be signed by a "LocalCA" (like they exists in many enterprise companies ) or by signing them from Let's Encrypt via DNS-01 challenge. The DNS challenge is automatically deployed on AWS Route53 and removed after authorisation.

Certificates are saved in an output folder. From there you can further proceed with using them (e.G Packing or a configuration managemet).
 
cert-master should only be used on a dedicated and secured server!

# Requirements

- python3

# Install

```
# Clone Repository
# Create a Virtual enviroment:
python3 -m venv venv
# install requirements
pip install -r requirements.txt
```

# Usage

```
cert-master.py --config conf/config.yaml -v
```

# Configuration

tbd