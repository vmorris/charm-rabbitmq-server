# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import sys
import subprocess
import glob
import tempfile
import random
import time

from rabbitmq_context import (
    RabbitMQSSLContext,
    RabbitMQClusterContext,
)

from charmhelpers.core.templating import render

from charmhelpers.contrib.openstack.utils import (
    _determine_os_workload_status,
    pause_unit,
    resume_unit,
    is_unit_paused_set,
)

from charmhelpers.core.hookenv import (
    relation_ids,
    related_units,
    log, ERROR,
    INFO,
    service_name,
    status_set,
    cached,
    relation_set,
)

from charmhelpers.core.host import (
    pwgen,
    mkdir,
    write_file,
    lsb_release,
    cmp_pkgrevno,
    path_hash,
    service as system_service,
)

from charmhelpers.contrib.peerstorage import (
    peer_store,
    peer_retrieve
)

from socket import gethostname as get_local_nodename

from collections import OrderedDict

PACKAGES = ['rabbitmq-server', 'python-amqplib', 'lockfile-progs']

RABBITMQ_CTL = '/usr/sbin/rabbitmqctl'
COOKIE_PATH = '/var/lib/rabbitmq/.erlang.cookie'
ENV_CONF = '/etc/rabbitmq/rabbitmq-env.conf'
RABBITMQ_CONF = '/etc/rabbitmq/rabbitmq.config'
ENABLED_PLUGINS = '/etc/rabbitmq/enabled_plugins'
RABBIT_USER = 'rabbitmq'
LIB_PATH = '/var/lib/rabbitmq/'
HOSTS_FILE = '/etc/hosts'

_named_passwd = '/var/lib/charm/{}/{}.passwd'
_local_named_passwd = '/var/lib/charm/{}/{}.local_passwd'


# hook_contexts are used as a convenient mechanism to render templates
# logically, consider building a hook_context for template rendering so
# the charm doesn't concern itself with template specifics etc.

CONFIG_FILES = OrderedDict([
    (RABBITMQ_CONF, {
        'hook_contexts': [
            RabbitMQSSLContext(),
            RabbitMQClusterContext(),
        ],
        'services': ['rabbitmq-server']
    }),
    (ENV_CONF, {
        'hook_contexts': None,
        'services': ['rabbitmq-server']
    }),
    (ENABLED_PLUGINS, {
        'hook_contexts': None,
        'services': ['rabbitmq-server']
    }),
])


class ConfigRenderer(object):
    """
    This class is a generic configuration renderer for
    a given dict mapping configuration files and hook_contexts.
    """
    def __init__(self, config):
        """
        :param config: see CONFIG_FILES
        :type config: dict
        """
        self.config_data = {}

        for config_path, data in config.items():
            hook_contexts = data.get('hook_contexts', None)
            if hook_contexts:
                ctxt = {}
                for svc_context in hook_contexts:
                    ctxt.update(svc_context())
                self.config_data[config_path] = ctxt

    def write(self, config_path):
        data = self.config_data.get(config_path, None)
        if data:
            log("writing config file: %s , data: %s" % (config_path,
                                                        str(data)),
                level='DEBUG')

            render(os.path.basename(config_path), config_path,
                   data, perms=0o644)

    def write_all(self):
        """Write all the defined configuration files"""
        for service in self.config_data.keys():
            self.write(service)

    def complete_contexts(self):
        return []


class RabbitmqError(Exception):
    pass


def list_vhosts():
    """
    Returns a list of all the available vhosts
    """
    try:
        output = subprocess.check_output([RABBITMQ_CTL, 'list_vhosts'])

        # NOTE(jamespage): Earlier rabbitmqctl versions append "...done"
        #                  to the output of list_vhosts
        if '...done' in output:
            return output.split('\n')[1:-2]
        else:
            return output.split('\n')[1:-1]
    except Exception as ex:
        # if no vhosts, just raises an exception
        log(str(ex), level='DEBUG')
        return []


def vhost_exists(vhost):
    return vhost in list_vhosts()


def create_vhost(vhost):
    if vhost_exists(vhost):
        return
    rabbitmqctl('add_vhost', vhost)
    log('Created new vhost (%s).' % vhost)


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
        log('Creating new user (%s).' % user)
        rabbitmqctl('add_user', user, password)

    if admin == is_admin:
        return

    if admin:
        log('Granting user (%s) admin access.' % user)
        rabbitmqctl('set_user_tags', user, 'administrator')
    else:
        log('Revoking user (%s) admin access.' % user)
        rabbitmqctl('set_user_tags', user)


def grant_permissions(user, vhost):
    log("Granting permissions", level='DEBUG')
    rabbitmqctl('set_permissions', '-p',
                vhost, user, '.*', '.*', '.*')


def set_policy(vhost, policy_name, match, value):
    log("setting policy", level='DEBUG')
    rabbitmqctl('set_policy', '-p', vhost,
                policy_name, match, value)


@cached
def caching_cmp_pkgrevno(package, revno, pkgcache=None):
    return cmp_pkgrevno(package, revno, pkgcache)


def set_ha_mode(vhost, mode, params=None, sync_mode='automatic'):
    """Valid mode values:

      * 'all': Queue is mirrored across all nodes in the cluster. When a new
         node is added to the cluster, the queue will be mirrored to that node.
      * 'exactly': Queue is mirrored to count nodes in the cluster.
      * 'nodes': Queue is mirrored to the nodes listed in node names

    More details at http://www.rabbitmq.com./ha.html

    :param vhost: virtual host name
    :param mode: ha mode
    :param params: values to pass to the policy, possible values depend on the
                   mode chosen.
    :param sync_mode: when `mode` is 'exactly' this used to indicate how the
                      sync has to be done
                      http://www.rabbitmq.com./ha.html#eager-synchronisation
    """

    if caching_cmp_pkgrevno('rabbitmq-server', '3.0.0') < 0:
        log(("Mirroring queues cannot be enabled, only supported "
             "in rabbitmq-server >= 3.0"), level='WARN')
        log(("More information at http://www.rabbitmq.com/blog/"
             "2012/11/19/breaking-things-with-rabbitmq-3-0"), level='INFO')
        return

    if mode == 'all':
        value = '{"ha-mode": "all", "ha-sync-mode": "%s"}' % sync_mode
    elif mode == 'exactly':
        value = '{"ha-mode":"exactly","ha-params":%s,"ha-sync-mode":"%s"}' \
                % (params, sync_mode)
    elif mode == 'nodes':
        value = '{"ha-mode":"nodes","ha-params":[%s]},"ha-sync-mode": "%s"' % (
            ",".join(params), sync_mode)
    else:
        raise RabbitmqError(("Unknown mode '%s', known modes: "
                             "all, exactly, nodes"))

    log("Setting HA policy to vhost '%s'" % vhost, level='INFO')
    set_policy(vhost, 'HA', '^(?!amq\.).*', value)


def clear_ha_mode(vhost, name='HA', force=False):
    """
    Clear policy from the `vhost` by `name`
    """
    if cmp_pkgrevno('rabbitmq-server', '3.0.0') < 0:
        log(("Mirroring queues not supported "
             "in rabbitmq-server >= 3.0"), level='WARN')
        log(("More information at http://www.rabbitmq.com/blog/"
             "2012/11/19/breaking-things-with-rabbitmq-3-0"), level='INFO')
        return

    log("Clearing '%s' policy from vhost '%s'" % (name, vhost), level='INFO')
    try:
        rabbitmqctl('clear_policy', '-p', vhost, name)
    except subprocess.CalledProcessError as ex:
        if not force:
            raise ex


def set_all_mirroring_queues(enable):
    """
    :param enable: if True then enable mirroring queue for all the vhosts,
                   otherwise the HA policy is removed
    """
    if cmp_pkgrevno('rabbitmq-server', '3.0.0') < 0:
        log(("Mirroring queues not supported "
             "in rabbitmq-server >= 3.0"), level='WARN')
        log(("More information at http://www.rabbitmq.com/blog/"
             "2012/11/19/breaking-things-with-rabbitmq-3-0"), level='INFO')
        return

    if enable:
        status_set('active', 'Enabling queue mirroring')
    else:
        status_set('active', 'Disabling queue mirroring')

    for vhost in list_vhosts():
        if enable:
            set_ha_mode(vhost, 'all')
        else:
            clear_ha_mode(vhost, force=True)


def rabbitmqctl(action, *args):
    ''' Run rabbitmqctl with action and args. This function uses
        subprocess.check_call. For uses that need check_output
        use a direct subproecess call
     '''
    cmd = [RABBITMQ_CTL, action]
    for arg in args:
        cmd.append(arg)
    log("Running {}".format(cmd), 'DEBUG')
    subprocess.check_call(cmd)


def wait_app():
    ''' Wait until rabbitmq has fully started '''
    run_dir = '/var/run/rabbitmq/'
    if os.path.isdir(run_dir):
        pid_file = run_dir + 'pid'
    else:
        pid_file = '/var/lib/rabbitmq/mnesia/rabbit@' \
                   + get_local_nodename() + '.pid'
    status_set('maintenance', 'Waiting for rabbitmq app to start: {}'
               ''.format(pid_file))
    try:
        rabbitmqctl('wait', pid_file)
        log('Confirmed rabbitmq app is running')
        return True
    except:
        status_set('blocked', 'Rabbitmq failed to start')
        try:
            status_cmd = ['rabbitmqctl', 'status']
            log(subprocess.check_output(status_cmd), 'DEBUG')
        except:
            pass
        return False


def start_app():
    ''' Start the rabbitmq app and wait until it is fully started '''
    status_set('maintenance', 'Starting rabbitmq applilcation')
    rabbitmqctl('start_app')
    wait_app()


def join_cluster(node):
    ''' Join cluster with node '''
    if cmp_pkgrevno('rabbitmq-server', '3.0.1') >= 0:
        cluster_cmd = 'join_cluster'
    else:
        cluster_cmd = 'cluster'
    status_set('maintenance',
               'Clustering with remote rabbit host (%s).' % node)
    rabbitmqctl('stop_app')
    # Intentionally using check_output so we can see rabbitmqctl error
    # message if it fails
    cmd = [RABBITMQ_CTL, cluster_cmd, node]
    subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    start_app()
    log('Host clustered with %s.' % node, 'INFO')


def cluster_with():
    log('Clustering with new node')

    if clustered():
        log('Node is already clustered, skipping')
        return False

    # check the leader and try to cluster with it
    node = leader_node()
    if node:
        if node in running_nodes():
            log('Host already clustered with %s.' % node)
            return False
        # NOTE: The primary problem rabbitmq has clustering is when
        # more than one node attempts to cluster at the same time.
        # The asynchronous nature of hook firing nearly guarantees
        # this. Using random time wait is a hack until we can
        # implement charmhelpers.coordinator.
        status_set('maintenance',
                   'Random wait for join_cluster to avoid collisions')
        time.sleep(random.random() * 100)
        try:
            join_cluster(node)
            # NOTE: toggle the cluster relation to ensure that any peers
            #       already clustered re-assess status correctly
            relation_set(clustered=get_local_nodename())
            return True
        except subprocess.CalledProcessError as e:
            status_set('blocked', 'Failed to cluster with %s. Exception: %s'
                       % (node, e))
            start_app()
    else:
        status_set('waiting', 'Leader not available for clustering')
        return False

    return False


def break_cluster():
    try:
        rabbitmqctl('stop_app')
        rabbitmqctl('reset')
        start_app()
        log('Cluster successfully broken.')
    except:
        # error, no nodes available for clustering
        log('Error breaking rabbit cluster', level=ERROR)
        raise


def update_rmq_env_conf(hostname=None, ipv6=False):
    """Update or append environment config.

    rabbitmq.conf.d is not present on all releases, so use or create
    rabbitmq-env.conf instead.
    """

    keyvals = {}
    if ipv6:
        keyvals['RABBITMQ_SERVER_START_ARGS'] = "'-proto_dist inet6_tcp'"

    if hostname:
        keyvals['RABBITMQ_NODENAME'] = hostname

    out = []
    keys_found = []
    if os.path.exists(ENV_CONF):
        for line in open(ENV_CONF).readlines():
            for key, val in keyvals.items():
                if line.strip().startswith(key):
                    keys_found.append(key)
                    line = '%s=%s' % (key, val)

            out.append(line)

    for key, val in keyvals.items():
        log('Updating %s, %s=%s' % (ENV_CONF, key, val))
        if key not in keys_found:
            out.append('%s=%s' % (key, val))

    with open(ENV_CONF, 'wb') as conf:
        conf.write('\n'.join(out))
        # Ensure newline at EOF
        conf.write('\n')


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
        log("command %s return non-zero." % cmd, level=ERROR)
    return (stdout, stderr, rc)


def get_rabbit_password_on_disk(username, password=None, local=False):
    ''' Retrieve, generate or store a rabbit password for
    the provided username on disk'''
    if local:
        _passwd_file = _local_named_passwd.format(service_name(), username)
    else:
        _passwd_file = _named_passwd.format(service_name(), username)

    _password = None
    if os.path.exists(_passwd_file):
        with open(_passwd_file, 'r') as passwd:
            _password = passwd.read().strip()
    else:
        mkdir(os.path.dirname(_passwd_file), owner=RABBIT_USER,
              group=RABBIT_USER, perms=0o775)
        os.chmod(os.path.dirname(_passwd_file), 0o775)
        _password = password or pwgen(length=64)
        write_file(_passwd_file, _password, owner=RABBIT_USER,
                   group=RABBIT_USER, perms=0o660)

    return _password


def migrate_passwords_to_peer_relation():
    '''Migrate any passwords storage on disk to cluster peer relation'''
    for f in glob.glob('/var/lib/charm/{}/*.passwd'.format(service_name())):
        _key = os.path.basename(f)
        with open(f, 'r') as passwd:
            _value = passwd.read().strip()
        try:
            peer_store(_key, _value)
            os.unlink(f)
        except ValueError:
            # NOTE cluster relation not yet ready - skip for now
            pass


def get_rabbit_password(username, password=None, local=False):
    ''' Retrieve, generate or store a rabbit password for
    the provided username using peer relation cluster'''
    if local:
        return get_rabbit_password_on_disk(username, password, local)
    else:
        migrate_passwords_to_peer_relation()
        _key = '{}.passwd'.format(username)
        try:
            _password = peer_retrieve(_key)
            if _password is None:
                _password = password or pwgen(length=64)
                peer_store(_key, _password)
        except ValueError:
            # cluster relation is not yet started, use on-disk
            _password = get_rabbit_password_on_disk(username, password)
        return _password


def bind_ipv6_interface():
    out = "RABBITMQ_SERVER_START_ARGS='-proto_dist inet6_tcp'\n"
    with open(ENV_CONF, 'wb') as conf:
        conf.write(out)


def update_hosts_file(map):
    """Rabbitmq does not currently like ipv6 addresses so we need to use dns
    names instead. In order to make them resolvable we ensure they are  in
    /etc/hosts.

    """
    with open(HOSTS_FILE, 'r') as hosts:
        lines = hosts.readlines()

    log("Updating hosts file with: %s (current: %s)" % (map, lines),
        level=INFO)

    newlines = []
    for ip, hostname in map.items():
        if not ip or not hostname:
            continue

        keepers = []
        for line in lines:
            _line = line.split()
            if len(line) < 2 or not (_line[0] == ip or hostname in _line[1:]):
                keepers.append(line)
            else:
                log("Removing line '%s' from hosts file" % (line))

        lines = keepers
        newlines.append("%s %s\n" % (ip, hostname))

    lines += newlines

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        with open(tmpfile.name, 'w') as hosts:
            for line in lines:
                hosts.write(line)

    os.rename(tmpfile.name, HOSTS_FILE)
    os.chmod(HOSTS_FILE, 0o644)


def assert_charm_supports_ipv6():
    """Check whether we are able to support charms ipv6."""
    if lsb_release()['DISTRIB_CODENAME'].lower() < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")


def restart_map():
    '''Determine the correct resource map to be passed to
    charmhelpers.core.restart_on_change() based on the services configured.

    :returns: dict: A dictionary mapping config file to lists of services
                    that should be restarted when file changes.
    '''
    _map = []
    for f, ctxt in CONFIG_FILES.iteritems():
        svcs = []
        for svc in ctxt['services']:
            svcs.append(svc)
        if svcs:
            _map.append((f, svcs))
    return OrderedDict(_map)


def services():
    ''' Returns a list of services associate with this charm '''
    _services = []
    for v in restart_map().values():
        _services = _services + v
    return list(set(_services))


@cached
def running_nodes():
    ''' Determine the current set of running rabbitmq-units in the cluster '''
    out = subprocess.check_output([RABBITMQ_CTL, 'cluster_status'])

    running_nodes = []
    m = re.search("\{running_nodes,\[(.*?)\]\}", out.strip(), re.DOTALL)
    if m is not None:
        running_nodes = m.group(1).split(',')
        running_nodes = [x.replace("'", '').strip() for x in running_nodes]

    return running_nodes


@cached
def leader_node():
    ''' Provide the leader node for clustering '''
    # Each rabbitmq node should join_cluster with the leader
    # to avoid split-brain clusters.
    leader_nodename = peer_retrieve('leader_nodename')
    if leader_nodename:
        return "rabbit@{}".format(leader_nodename)
    else:
        return None


@cached
def clustered():
    ''' Determine whether local rabbitmq-server is clustered '''
    # NOTE: A rabbitmq node can only join a cluster once.
    # Simply checking for more than one running node tells us
    # if this unit is in a cluster.
    if len(running_nodes()) > 1:
        return True
    else:
        return False


def assess_cluster_status(*args):
    ''' Assess the status for the current running unit '''
    # NOTE: ensure rabbitmq is actually installed before doing
    #       any checks
    if os.path.exists(RABBITMQ_CTL):
        # Clustering Check
        peer_ids = relation_ids('cluster')
        if peer_ids and len(related_units(peer_ids[0])):
            if not clustered():
                return 'waiting', 'Unit has peers, but RabbitMQ not clustered'
        # General status check
        ret = wait_app()
        if ret:
            # we're active - so just return the 'active' state, but if 'active'
            # is returned, then it is ignored by the assess_status system.
            return 'active', "message is ignored"
    else:
        return 'waiting', 'RabbitMQ is not yet installed'


def restart_on_change(restart_map, stopstart=False):
    """Restart services based on configuration files changing

    This function is used a decorator, for example::

        @restart_on_change({
            '/etc/ceph/ceph.conf': [ 'cinder-api', 'cinder-volume' ]
            '/etc/apache/sites-enabled/*': [ 'apache2' ]
            })
        def config_changed():
            pass  # your code here

    In this example, the cinder-api and cinder-volume services
    would be restarted if /etc/ceph/ceph.conf is changed by the
    ceph_client_changed function. The apache2 service would be
    restarted if any file matching the pattern got changed, created
    or removed. Standard wildcards are supported, see documentation
    for the 'glob' module for more information.
    """
    def wrap(f):
        def wrapped_f(*args, **kwargs):
            if is_unit_paused_set():
                return f(*args, **kwargs)
            checksums = {path: path_hash(path) for path in restart_map}
            f(*args, **kwargs)
            restarts = []
            for path in restart_map:
                if path_hash(path) != checksums[path]:
                    restarts += restart_map[path]
            services_list = list(OrderedDict.fromkeys(restarts))
            status_set('maintenance',
                       'Random wait for restart to avoid collisions')
            time.sleep(random.random() * 100)
            if not stopstart:
                for svc_name in services_list:
                    system_service('restart', svc_name)
                    wait_app()
            else:
                for action in ['stop', 'start']:
                    for svc_name in services_list:
                        system_service(action, svc_name)
                        wait_app()
        return wrapped_f
    return wrap


def assess_status(configs):
    """Assess status of current unit
    Decides what the state of the unit should be based on the current
    configuration.
    SIDE EFFECT: calls set_os_workload_status(...) which sets the workload
    status of the unit.
    Also calls status_set(...) directly if paused state isn't complete.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    assess_status_func(configs)()


def assess_status_func(configs):
    """Helper function to create the function that will assess_status() for
    the unit.
    Uses charmhelpers.contrib.openstack.utils.make_assess_status_func() to
    create the appropriate status function and then returns it.
    Used directly by assess_status() and also for pausing and resuming
    the unit.

    NOTE(ajkavanagh) ports are not checked due to race hazards with services
    that don't behave sychronously w.r.t their service scripts.  e.g.
    apache2.
    @param configs: a templating.OSConfigRenderer() object
    @return f() -> None : a function that assesses the unit's workload status
    """
    def _assess_status_func():
        state, message = _determine_os_workload_status(
            configs, {},
            charm_func=assess_cluster_status,
            services=services(), ports=None)
        if state == 'active' and clustered():
            message = 'Unit is ready and clustered'
        status_set(state, message)

    return _assess_status_func


def pause_unit_helper(configs):
    """Helper function to pause a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.pause_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(resume_unit, configs)


def _pause_resume_helper(f, configs):
    """Helper function that uses the make_assess_status_func(...) from
    charmhelpers.contrib.openstack.utils to create an assess_status(...)
    function that can be used with the pause/resume of the unit
    @param f: the function to be used with the assess_status(...) function
    @returns None - this function is executed for its side-effect
    """
    # TODO(ajkavanagh) - ports= has been left off because of the race hazard
    # that exists due to service_start()
    f(assess_status_func(configs),
      services=services(),
      ports=None)
