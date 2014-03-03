import os
import re
import sys
import subprocess
import glob
import lib.utils as utils
import apt_pkg as apt

import _pythonpath
_ = _pythonpath

from charmhelpers.contrib.openstack.utils import get_hostname
from charmhelpers.core.hookenv import config, relation_ids, relation_get, relation_set, local_unit

PACKAGES = ['pwgen', 'rabbitmq-server', 'python-amqplib']

RABBITMQ_CTL = '/usr/sbin/rabbitmqctl'
COOKIE_PATH = '/var/lib/rabbitmq/.erlang.cookie'
ENV_CONF = '/etc/rabbitmq/rabbitmq-env.conf'
RABBITMQ_CONF = '/etc/rabbitmq/rabbitmq.config'
RABBIT_USER = 'rabbitmq'
LIB_PATH = '/var/lib/rabbitmq/'


def vhost_exists(vhost):
    cmd = [RABBITMQ_CTL, 'list_vhosts']
    out = subprocess.check_output(cmd)
    for line in out.split('\n')[1:]:
        if line == vhost:
            utils.juju_log('INFO', 'vhost (%s) already exists.' % vhost)
            return True
    return False


def create_vhost(vhost):
    if vhost_exists(vhost):
        return
    cmd = [RABBITMQ_CTL, 'add_vhost', vhost]
    subprocess.check_call(cmd)
    utils.juju_log('INFO', 'Created new vhost (%s).' % vhost)


def user_exists(user):
    cmd = [RABBITMQ_CTL, 'list_users']
    out = subprocess.check_output(cmd)
    for line in out.split('\n')[1:]:
        _user = line.split('\t')[0]
        if _user == user:
            admin = line.split('\t')[1]
            return True, (admin == '[administrator]')
    return False, False


def create_user(user, password, admin=False):
    exists, is_admin = user_exists(user)

    if not exists:
        cmd = [RABBITMQ_CTL, 'add_user', user, password]
        subprocess.check_call(cmd)
        utils.juju_log('INFO', 'Created new user (%s).' % user)

    if admin == is_admin:
        return

    if admin:
        cmd = [RABBITMQ_CTL, 'set_user_tags', user, 'administrator']
        utils.juju_log('INFO', 'Granting user (%s) admin access.')
    else:
        cmd = [RABBITMQ_CTL, 'set_user_tags', user]
        utils.juju_log('INFO', 'Revoking user (%s) admin access.')


def grant_permissions(user, vhost):
    cmd = [RABBITMQ_CTL, 'set_permissions', '-p',
           vhost, user, '.*', '.*', '.*']
    subprocess.check_call(cmd)


def service(action):
    cmd = ['service', 'rabbitmq-server', action]
    subprocess.check_call(cmd)


def compare_version(base_version):
    apt.init()
    cache = apt.Cache()
    pkg = cache['rabbitmq-server']
    if pkg.current_ver:
        return (apt.version_compare(pkg.current_ver.ver_str, base_version) >= 0)
    else:
        return False

def cluster_with():
    utils.juju_log('INFO', 'Clustering with new node')
    if compare_version('3.0.1-1'):
        cluster_cmd = 'join_cluster'
        cmd = [RABBITMQ_CTL, 'set_policy', 'HA', '^(?!amq\.).*', '{"ha-mode": "all"}']
        subprocess.check_call(cmd)
    else:
        cluster_cmd = 'cluster'
    out = subprocess.check_output([RABBITMQ_CTL, 'cluster_status'])
    current_host = subprocess.check_output(['hostname']).strip()

    # check if node is already clustered
    total_nodes = 1
    m = re.search("\{running_nodes,\[(.*)\]\}", out.strip())
    if m is not None:
        total_nodes = len(m.group(1).split(','))

    if total_nodes > 1:
        utils.juju_log('INFO', 'Node is already clustered, skipping')
    else:
        # check all peers and try to cluster with them
        available_nodes = []
        num_tries = 0
        for r_id in (utils.relation_ids('cluster') or []):
            for unit in (utils.relation_list(r_id) or []):
                address = utils.relation_get('private_address',
                                             rid=r_id, unit=unit)
                if address is not None:
                    node = get_hostname(address, fqdn=False)
                    if current_host != node:
                        available_nodes.append(node)
                else:
                    # node is down, add to max tries
                    num_tries += 1

        # iterate over all the nodes, join to the first available
        if len(available_nodes) == 0:
            utils.juju_log('INFO', 'Master node still not ready, retrying')
            return

        max_tries = config('max-cluster-tries')
        for node in available_nodes:
            utils.juju_log('INFO',
                           'Clustering with remote rabbit host (%s).' % node)
            for line in out.split('\n'):
                if re.search(node, line):
                    utils.juju_log('INFO',
                                   'Host already clustered with %s.' % node)
                    return

                try:
                    cmd = [RABBITMQ_CTL, 'stop_app']
                    subprocess.check_call(cmd)
                    cmd = [RABBITMQ_CTL, cluster_cmd, 'rabbit@%s' % node]
                    subprocess.check_call(cmd)
                    cmd = [RABBITMQ_CTL, 'start_app']
                    subprocess.check_call(cmd)
                    utils.juju_log('INFO', 'Host clustered with %s.' % node)
                    return
                except:
                    pass
            # continue to the next node
            num_tries += 1

        # error, no nodes available for clustering
        utils.juju_log('ERROR', 'No nodes available for clustering, retrying')
        if num_tries > max_tries:
            utils.juju_log('ERROR', 'Max tries number exhausted, exiting')
            sys.exit(1)


def break_cluster():
    try:
        cmd = [RABBITMQ_CTL, 'stop_app']
        subprocess.check_call(cmd)
        cmd = [RABBITMQ_CTL, 'reset']
        subprocess.check_call(cmd)
        cmd = [RABBITMQ_CTL, 'start_app']
        subprocess.check_call(cmd)
        utils.juju_log('INFO', 'Cluster successfully broken.')
        return
    except:
        # error, no nodes available for clustering
        utils.juju_log('ERROR', 'Error breaking rabbit cluster')
        sys.exit(1)


def set_node_name(name):
    # update or append RABBITMQ_NODENAME to environment config.
    # rabbitmq.conf.d is not present on all releases, so use or create
    # rabbitmq-env.conf instead.
    if not os.path.isfile(ENV_CONF):
        utils.juju_log('INFO', '%s does not exist, creating.' % ENV_CONF)
        with open(ENV_CONF, 'wb') as out:
            out.write('RABBITMQ_NODENAME=%s\n' % name)
        return

    out = []
    f = False
    for line in open(ENV_CONF).readlines():
        if line.strip().startswith('RABBITMQ_NODENAME'):
            f = True
            line = 'RABBITMQ_NODENAME=%s\n' % name
        out.append(line)
    if not f:
        out.append('RABBITMQ_NODENAME=%s\n' % name)
    utils.juju_log('INFO', 'Updating %s, RABBITMQ_NODENAME=%s' %
                   (ENV_CONF, name))
    with open(ENV_CONF, 'wb') as conf:
        conf.write(''.join(out))


def get_node_name():
    if not os.path.exists(ENV_CONF):
        return None
    env_conf = open(ENV_CONF, 'r').readlines()
    node_name = None
    for l in env_conf:
        if l.startswith('RABBITMQ_NODENAME'):
            node_name = l.split('=')[1].strip()
    return node_name


def _manage_plugin(plugin, action):
    os.environ['HOME'] = '/root'
    _rabbitmq_plugins = \
        glob.glob('/usr/lib/rabbitmq/lib/rabbitmq_server-*'
                  '/sbin/rabbitmq-plugins')[0]
    subprocess.check_call([_rabbitmq_plugins, action, plugin])


def enable_plugin(plugin):
    _manage_plugin(plugin, 'enable')


def disable_plugin(plugin):
    _manage_plugin(plugin, 'disable')

ssl_key_file = "/etc/rabbitmq/rabbit-server-privkey.pem"
ssl_cert_file = "/etc/rabbitmq/rabbit-server-cert.pem"


def enable_ssl(ssl_key, ssl_cert, ssl_port):
    with open(ssl_key_file, 'w') as key_file:
        key_file.write(ssl_key)
    utils.chmod(ssl_key_file, 0640)
    utils.chown(ssl_key_file, "root", RABBIT_USER)
    with open(ssl_cert_file, 'w') as cert_file:
        cert_file.write(ssl_cert)
    utils.chmod(ssl_cert_file, 0640)
    utils.chown(ssl_cert_file, "root", RABBIT_USER)
    with open(RABBITMQ_CONF, 'w') as rmq_conf:
        rmq_conf.write(utils.render_template(os.path.basename(RABBITMQ_CONF),
                                             {"ssl_port": ssl_port,
                                              "ssl_cert_file": ssl_cert_file,
                                              "ssl_key_file": ssl_key_file}))


def execute(cmd, die=False, echo=False):
    """ Executes a command

    if die=True, script will exit(1) if command does not return 0
    if echo=True, output of command will be printed to stdout

    returns a tuple: (stdout, stderr, return code)
    """
    p = subprocess.Popen(cmd.split(" "),
                         stdout=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout = ""
    stderr = ""

    def print_line(l):
        if echo:
            print l.strip('\n')
            sys.stdout.flush()

    for l in iter(p.stdout.readline, ''):
        print_line(l)
        stdout += l
    for l in iter(p.stderr.readline, ''):
        print_line(l)
        stderr += l

    p.communicate()
    rc = p.returncode

    if die and rc != 0:
        utils.juju_log('INFO', "ERROR: command %s return non-zero.\n" % cmd)
    return (stdout, stderr, rc)


def get_clustered_attribute(attribute_name):
    cluster_rels = relation_ids('cluster')
    if len(cluster_rels) > 0:
        cluster_rid = cluster_rels[0]
        password = relation_get(attribute=attribute_name, rid=cluster_rid, unit=local_unit())
        return password
    else:
        return None

def set_clustered_attribute(attribute_name, value):
    cluster_rels = relation_ids('cluster')
    if len(cluster_rels) > 0:
        cluster_rid = cluster_rels[0]
        relation_set(relation_id=cluster_rid, relation_settings={attribute_name: value})
