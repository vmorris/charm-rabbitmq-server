#!/usr/bin/python
#
# This Amulet test deploys rabbitmq-server
#
# Note: We use python2, because pika doesn't support python3
import amulet

# The number of seconds to wait for the environment to setup.
seconds = 1200 
d = amulet.Deployment(series="trusty")

d.add('rabbitmq-server', units=1)
# Create a configuration.
configuration = {'cluster-partition-handling': "autoheal"} 
d.configure('rabbitmq-server', configuration) 

d.expose('rabbitmq-server') 
try:
    d.setup(timeout=seconds)
    d.sentry.wait(seconds) 
except amulet.helpers.TimeoutError:
    message = 'The environment did not setup in %d seconds.' % seconds
    amulet.raise_status(amulet.SKIP, msg=message)
except:
    raise 

rabbit_unit = d.sentry.unit['rabbitmq-server/0'] 
output, code = rabbit_unit.run("grep autoheal /etc/rabbitmq/rabbitmq.conf") 

if code != 0 or output == "":
    amulet.raise_status(amulet.FAIL, msg=message)
