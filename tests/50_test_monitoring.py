#!/usr/bin/python3

# This Amulet test performs a basic deploy and checks if rabbitmq is running.

import amulet
import os
import time

# The number of seconds to wait for the environment to setup.
seconds = 900
# Get the directory in this way to load the files from the tests directory.
path = os.path.abspath(os.path.dirname(__file__))

key_path = os.path.join(path, 'rabbit-server-privkey.pem')
# Read the private key file.
with open(key_path) as f:
    privateKey = f.read()
# Read the certificate file.
cert_path = os.path.join(path, 'rabbit-server-cert.pem')
with open(cert_path) as f:
    certificate = f.read()

# Create a dictionary for the rabbitmq configuration.
rabbitmq_configuration = {
    'stats_cron_schedule': '*/1 * * * *'
}
d = amulet.Deployment(series='trusty')
# Add the rabbitmq-server charm to the deployment.
d.add('rabbitmq-server')
# Configure options on the rabbitmq-server.
d.configure('rabbitmq-server', rabbitmq_configuration)
# Expose the server so we can connect.
d.expose('rabbitmq-server')
# XXX Remove charm= once this branch lands in the charm store
d.add('nrpe-external-master',
      charm='lp:~gnuoy/charms/trusty/nrpe/services-rewrite')
d.relate('rabbitmq-server:nrpe-external-master',
         'nrpe-external-master:nrpe-external-master')

try:
    # Execute the deployer with the current mapping.
    d.setup(timeout=seconds)
except amulet.helpers.TimeoutError:
    message = 'The environment did not setup in %d seconds.' % seconds
    # The SKIP status enables skip or fail the test based on configuration.
    amulet.raise_status(amulet.SKIP, msg=message)
except:
    raise
print('The rabbitmq-server has been successfully deployed and related '
      'to nrpe-external-master.')

###############################################################################
# # Verify nagios checks
###############################################################################
rabbitmq_sentry = d.sentry.unit['rabbitmq-server/0']

command = 'bash -c "$(egrep -oh /usr/local.* ' \
          '/etc/nagios/nrpe.d/check_rabbitmq.cfg)"'
print(command)
output, code = rabbitmq_sentry.run(command)
print(output)
if (code != 0):
    message = 'The ' + command + ' did not return the expected code of 0.'
    amulet.raise_status(amulet.FAIL, msg=message)
else:
    print('The rabbitmq-server check_rabbitmq is OK')

print('Sleeping 70 seconds to make sure the monitoring cron has run')
time.sleep(70)

command = 'bash -c "$(egrep -oh /usr/local.* ' \
          '/etc/nagios/nrpe.d/check_rabbitmq_queue.cfg)"'
print(command)
output, code = rabbitmq_sentry.run(command)
print(output)
if (code != 0):
    message = 'The ' + command + ' did not return the expected code of 0.'
    amulet.raise_status(amulet.FAIL, msg=message)
else:
    print('The rabbitmq-server check_rabbitmq_queue is OK')

# Success!
print('The rabbitmq-server passed the monitoring tests!')
