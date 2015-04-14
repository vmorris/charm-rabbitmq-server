# Copyright 2015 Canonical Limited.
# This file provides common functions for amulet tests for the rabbitmq-server
# juju charm.

import os
from charmhelpers.contrib.ssl.service import ServiceCA

# The name of the rabbit certificate authority.
CA_NAME = 'rabbit-server-ca'

# Put the certificate authority in a temporary location since
# it is rebuilt for each amulet run.
CA_PATH = '/tmp/rabbit-server-ca'

# The common name for the certificate itself.
COMMON_NAME = 'rabbitmq-server'

CA = ServiceCA(CA_NAME, CA_PATH)
CA.init()
CA.get_or_create_cert(COMMON_NAME)


def _load_file(path):
    contents = None
    with open(path) as f:
        contents = f.read()
    return contents


def get_key():
    """
    Returns the contents of the rabbitmq private key.
    """
    key_path = os.path.join(CA_PATH, 'certs', 'rabbitmq-server.key')
    return _load_file(key_path)


def get_cert():
    """
    Returns the contents of the rabbitmq certificate.
    """
    cert_path = os.path.join(CA_PATH, 'certs', 'rabbitmq-server.crt')
    return _load_file(cert_path)


def ca_cert_path():
    """
    Returns the certificate authority certificate path.
    """
    return os.path.join(CA_PATH, 'cacert.pem')
