#!/bin/sh

# The script installs amulet and other tools needed for the amulet tests.

set -x 

# Get the status of the amulet package, this returns 0 of package is installed.
dpkg -s amulet
if [ $? -ne 0 ]; then
  # Install the Amulet testing harness.
  sudo add-apt-repository -y ppa:juju/stable
  sudo apt-get update 
  sudo apt-get install -y amulet juju-core charm-tools
fi
dpkg -s python3
if [ $? -ne 0 ]; then
  # Install the Python3 libraries.
  sudo apt-get install -y python3
fi

dpkg -s amqp-tools
if [ $? -ne 0 ]; then
  sudo apt-get install -y amqp-tools
fi
