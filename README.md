# Info

cert-master manages certificates in a central system. Currently certificates signed by a "LocalCA" (like they exists in many enterprise companies ) or by signing them bei Let's Encrypt via DNS-01 challenge. The DNS challenge is automaticly deployed on AWS Route53 and removed after authorisation.

> Software is in an alpha state!

Certificates are saved in a output folder. From there you can further proceed with using them.
 
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