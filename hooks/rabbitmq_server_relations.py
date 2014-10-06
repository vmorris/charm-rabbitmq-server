#!/usr/bin/python
import base64
import os
import shutil
import sys
import subprocess
import glob
import socket

import rabbit_utils as rabbit
from lib.utils import (
    chown, chmod,
    is_newer,
)
from charmhelpers.contrib.hahelpers.cluster import (
    is_clustered,
    eligible_leader
)
from charmhelpers.contrib.openstack.utils import (
    get_hostname,
    get_host_ip
)

from charmhelpers.contrib.network.ip import (
    get_ipv6_addr
)

import charmhelpers.contrib.storage.linux.ceph as ceph
from charmhelpers.contrib.openstack.utils import save_script_rc

from charmhelpers.fetch import (
    add_source,
    apt_update,
    apt_install)

from charmhelpers.core.hookenv import (
    open_port, close_port,
    log, ERROR,
    relation_get,
    relation_set,
    relation_ids,
    related_units,
    service_name,
    local_unit,
    relations_of_type,
    config,
    unit_get,
    is_relation_made,
    Hooks,
    UnregisteredHookError
)
from charmhelpers.core.host import (
    rsync, service_stop, service_restart, cmp_pkgrevno
)
from charmhelpers.contrib.charmsupport.nrpe import NRPE
from charmhelpers.contrib.ssl.service import ServiceCA

from charmhelpers.contrib.peerstorage import (
    peer_echo,
    peer_retrieve,
    peer_store,
    peer_store_and_set,
    peer_retrieve_by_prefix,
)

hooks = Hooks()

SERVICE_NAME = os.getenv('JUJU_UNIT_NAME').split('/')[0]
POOL_NAME = SERVICE_NAME
RABBIT_DIR = '/var/lib/rabbitmq'
RABBIT_USER = 'rabbitmq'
RABBIT_GROUP = 'rabbitmq'
NAGIOS_PLUGINS = '/usr/local/lib/nagios/plugins'


@hooks.hook('install')
def install():
    pre_install_hooks()
    # NOTE(jamespage) install actually happens in config_changed hook


def configure_amqp(username, vhost, admin=False):
    # get and update service password
    password = rabbit.get_rabbit_password(username)

    # update vhost
    rabbit.create_vhost(vhost)
    rabbit.create_user(username, password, admin)
    rabbit.grant_permissions(username, vhost)

    return password


@hooks.hook('amqp-relation-changed')
def amqp_changed(relation_id=None, remote_unit=None):
    if not eligible_leader('res_rabbitmq_vip'):
        # Each unit needs to set the db information otherwise if the unit
        # with the info dies the settings die with it Bug# 1355848
        for rel_id in relation_ids('amqp'):
            peerdb_settings = peer_retrieve_by_prefix(rel_id,
                                                      exc_list=['hostname'])
            peerdb_settings['hostname'] = unit_get('private-address')
            if 'password' in peerdb_settings:
                relation_set(relation_id=rel_id, **peerdb_settings)
        log('amqp_changed(): Deferring amqp_changed'
            ' to eligible_leader.')

        # NOTE: active/active case
        if config('prefer-ipv6'):
            relation_settings = {'private-address': get_ipv6_addr()[0]}
            relation_set(relation_settings=relation_settings)
        return

    relation_settings = {}
    settings = relation_get(rid=relation_id, unit=remote_unit)

    singleset = set(['username', 'vhost'])

    if singleset.issubset(settings):
        if None in [settings['username'], settings['vhost']]:
            log('amqp_changed(): Relation not ready.')
            return

        relation_settings['password'] = configure_amqp(
            username=settings['username'],
            vhost=settings['vhost'],
            admin=settings.get('admin', False))
    else:
        queues = {}
        for k, v in settings.iteritems():
            amqp = k.split('_')[0]
            x = '_'.join(k.split('_')[1:])
            if amqp not in queues:
                queues[amqp] = {}
            queues[amqp][x] = v
        for amqp in queues:
            if singleset.issubset(queues[amqp]):
                relation_settings[
                    '_'.join([amqp, 'password'])] = configure_amqp(
                    queues[amqp]['username'],
                    queues[amqp]['vhost'])

    if config('prefer-ipv6'):
        relation_settings['private-address'] = get_ipv6_addr()[0]
    else:
        relation_settings['hostname'] = unit_get('private-address')

    configure_client_ssl(relation_settings)

    if is_clustered():
        relation_settings['clustered'] = 'true'
        if is_relation_made('ha'):
            # active/passive settings
            relation_settings['vip'] = config('vip')
            # or ha-vip-only to support active/active, but
            # accessed via a VIP for older clients.
            if config('ha-vip-only') is True:
                relation_settings['ha-vip-only'] = 'true'

    if relation_id:
        relation_settings['rid'] = relation_id

    # set if need HA queues or not
    if cmp_pkgrevno('rabbitmq-server', '3.0.1') < 0:
        relation_settings['ha_queues'] = True
    peer_store_and_set(relation_settings=relation_settings)


@hooks.hook('cluster-relation-joined')
def cluster_joined(relation_id=None):
    if config('prefer-ipv6'):
        relation_settings = {'hostname': socket.gethostname(),
                             'private-address': get_ipv6_addr()[0]}
        relation_set(relation_id=relation_id,
                     relation_settings=relation_settings)

    if is_relation_made('ha') and \
            config('ha-vip-only') is False:
        log('hacluster relation is present, skipping native '
            'rabbitmq cluster config.')
        return

    # Set RABBITMQ_NODENAME to something that's resolvable by my peers
    # get_host_ip() is called to sanitize private-address in case it
    # doesn't return an IP address
    nodename = get_hostname(get_host_ip(unit_get('private-address')),
                            fqdn=False)
    if nodename:
        log('forcing nodename=%s' % nodename)
        # need to stop it under current nodename
        service_stop('rabbitmq-server')
        rabbit.set_node_name('rabbit@%s' % nodename)
        service_restart('rabbitmq-server')

    if is_newer():
        log('cluster_joined: Relation greater.')
        return

    rabbit.COOKIE_PATH = '/var/lib/rabbitmq/.erlang.cookie'
    if not os.path.isfile(rabbit.COOKIE_PATH):
        log('erlang cookie missing from %s' % rabbit.COOKIE_PATH,
            level=ERROR)
        return
    cookie = open(rabbit.COOKIE_PATH, 'r').read().strip()
    peer_store('cookie', cookie)


@hooks.hook('cluster-relation-changed')
def cluster_changed():
    rdata = relation_get()
    if 'cookie' not in rdata:
        log('cluster_joined: cookie not yet set.')
        return

    if config('prefer-ipv6') and rdata.get('hostname'):
        private_address = rdata['private-address']
        hostname = rdata['hostname']
        rabbit.render_hosts(private_address, hostname)

    # sync passwords
    peer_echo(['cookie', 'password'])

    # sync cookie
    cookie = peer_retrieve('cookie')
    if open(rabbit.COOKIE_PATH, 'r').read().strip() == cookie:
        log('Cookie already synchronized with peer.')
    else:
        log('Synchronizing erlang cookie from peer.')
        rabbit.service('stop')
        with open(rabbit.COOKIE_PATH, 'wb') as out:
            out.write(cookie)
        rabbit.service('start')

    if is_relation_made('ha') and \
            config('ha-vip-only') is False:
        log('hacluster relation is present, skipping native '
            'rabbitmq cluster config.')
        return

    # cluster with node
    if is_newer():
        if rabbit.cluster_with():
            # resync nrpe user after clustering
            update_nrpe_checks()
    # If cluster has changed peer db may have changed so run amqp_changed
    # to sync any changes
    for rid in relation_ids('amqp'):
        for unit in related_units(rid):
            amqp_changed(relation_id=rid, remote_unit=unit)


@hooks.hook('cluster-relation-departed')
def cluster_departed():
    if is_relation_made('ha') and \
            config('ha-vip-only') is False:
        log('hacluster relation is present, skipping native '
            'rabbitmq cluster config.')
        return
    if not is_newer():
        log('cluster_joined: Relation lesser.')
        return
    rabbit.break_cluster()


@hooks.hook('ha-relation-joined')
def ha_joined():
    corosync_bindiface = config('ha-bindiface')
    corosync_mcastport = config('ha-mcastport')
    vip = config('vip')
    vip_iface = config('vip_iface')
    vip_cidr = config('vip_cidr')
    rbd_name = config('rbd-name')
    vip_only = config('ha-vip-only')

    if None in [corosync_bindiface, corosync_mcastport, vip, vip_iface,
                vip_cidr, rbd_name] and vip_only is False:
        log('Insufficient configuration data to configure hacluster.',
            level=ERROR)
        sys.exit(1)
    elif None in [corosync_bindiface, corosync_mcastport, vip, vip_iface,
                  vip_cidr] and vip_only is True:
        log('Insufficient configuration data to configure VIP-only hacluster.',
            level=ERROR)
        sys.exit(1)

    if not is_relation_made('ceph', 'auth') and vip_only is False:
        log('ha_joined: No ceph relation yet, deferring.')
        return

    name = '%s@localhost' % SERVICE_NAME
    if rabbit.get_node_name() != name and vip_only is False:
        log('Stopping rabbitmq-server.')
        service_stop('rabbitmq-server')
        rabbit.set_node_name('%s@localhost' % SERVICE_NAME)
    else:
        log('Node name already set to %s.' % name)

    relation_settings = {}
    relation_settings['corosync_bindiface'] = corosync_bindiface
    relation_settings['corosync_mcastport'] = corosync_mcastport

    if vip_only is True:
        relation_settings['resources'] = {
            'res_rabbitmq_vip': 'ocf:heartbeat:IPaddr2',
        }
        relation_settings['resource_params'] = {
            'res_rabbitmq_vip': 'params ip="%s" cidr_netmask="%s" nic="%s"' %
                                (vip, vip_cidr, vip_iface),
        }
    else:
        relation_settings['resources'] = {
            'res_rabbitmq_rbd': 'ocf:ceph:rbd',
            'res_rabbitmq_fs': 'ocf:heartbeat:Filesystem',
            'res_rabbitmq_vip': 'ocf:heartbeat:IPaddr2',
            'res_rabbitmq-server': 'lsb:rabbitmq-server',
        }

        relation_settings['resource_params'] = {
            'res_rabbitmq_rbd': 'params name="%s" pool="%s" user="%s" '
                                'secret="%s"' %
                                (rbd_name, POOL_NAME,
                                 SERVICE_NAME, ceph._keyfile_path(
                                     SERVICE_NAME)),
            'res_rabbitmq_fs': 'params device="/dev/rbd/%s/%s" directory="%s" '
                               'fstype="ext4" op start start-delay="10s"' %
                               (POOL_NAME, rbd_name, RABBIT_DIR),
            'res_rabbitmq_vip': 'params ip="%s" cidr_netmask="%s" nic="%s"' %
                                (vip, vip_cidr, vip_iface),
            'res_rabbitmq-server': 'op start start-delay="5s" '
                                   'op monitor interval="5s"',
        }

        relation_settings['groups'] = {
            'grp_rabbitmq':
            'res_rabbitmq_rbd res_rabbitmq_fs res_rabbitmq_vip '
            'res_rabbitmq-server',
        }

    for rel_id in relation_ids('ha'):
        relation_set(relation_id=rel_id, relation_settings=relation_settings)

    env_vars = {
        'OPENSTACK_PORT_EPMD': 4369,
        'OPENSTACK_PORT_MCASTPORT': config('ha-mcastport'),
    }
    save_script_rc(**env_vars)


@hooks.hook('ha-relation-changed')
def ha_changed():
    if not is_clustered():
        return
    vip = config('vip')
    log('ha_changed(): We are now HA clustered. '
        'Advertising our VIP (%s) to all AMQP clients.' %
        vip)
    # need to re-authenticate all clients since node-name changed.
    for rid in relation_ids('amqp'):
        for unit in related_units(rid):
            amqp_changed(relation_id=rid, remote_unit=unit)


@hooks.hook('ceph-relation-joined')
def ceph_joined():
    log('Start Ceph Relation Joined')
    # NOTE fixup
    # utils.configure_source()
    ceph.install()
    log('Finish Ceph Relation Joined')


@hooks.hook('ceph-relation-changed')
def ceph_changed():
    log('Start Ceph Relation Changed')
    auth = relation_get('auth')
    key = relation_get('key')
    use_syslog = str(config('use-syslog')).lower()
    if None in [auth, key]:
        log('Missing key or auth in relation')
        sys.exit(0)

    ceph.configure(service=SERVICE_NAME, key=key, auth=auth,
                   use_syslog=use_syslog)

    if eligible_leader('res_rabbitmq_vip'):
        rbd_img = config('rbd-name')
        rbd_size = config('rbd-size')
        sizemb = int(rbd_size.split('G')[0]) * 1024
        blk_device = '/dev/rbd/%s/%s' % (POOL_NAME, rbd_img)
        # rbd_pool_rep_count = config('ceph-osd-replication-count')
        ceph.ensure_ceph_storage(service=SERVICE_NAME, pool=POOL_NAME,
                                 rbd_img=rbd_img, sizemb=sizemb,
                                 fstype='ext4', mount_point=RABBIT_DIR,
                                 blk_device=blk_device,
                                 system_services=['rabbitmq-server'])  # ,
        # rbd_pool_replicas=rbd_pool_rep_count)
        subprocess.check_call(['chown', '-R', '%s:%s' %
                               (RABBIT_USER, RABBIT_GROUP), RABBIT_DIR])
    else:
        log('This is not the peer leader. Not configuring RBD.')
        log('Stopping rabbitmq-server.')
        service_stop('rabbitmq-server')

    # If 'ha' relation has been made before the 'ceph' relation
    # it is important to make sure the ha-relation data is being
    # sent.
    if is_relation_made('ha'):
        log('*ha* relation exists. Triggering ha_joined()')
        ha_joined()
    else:
        log('*ha* relation does not exist.')
    log('Finish Ceph Relation Changed')


@hooks.hook('nrpe-external-master-relation-changed')
def update_nrpe_checks():
    if os.path.isdir(NAGIOS_PLUGINS):
        rsync(os.path.join(os.getenv('CHARM_DIR'), 'scripts',
                           'check_rabbitmq.py'),
              os.path.join(NAGIOS_PLUGINS, 'check_rabbitmq.py'))

    # Find out if nrpe set nagios_hostname
    hostname = None
    for rel in relations_of_type('nrpe-external-master'):
        if 'nagios_hostname' in rel:
            hostname = rel['nagios_hostname']
            break
    # create unique user and vhost for each unit
    current_unit = local_unit().replace('/', '-')
    user = 'nagios-%s' % current_unit
    vhost = 'nagios-%s' % current_unit
    password = rabbit.get_rabbit_password(user)

    rabbit.create_vhost(vhost)
    rabbit.create_user(user, password)
    rabbit.grant_permissions(user, vhost)

    nrpe_compat = NRPE(hostname=hostname)
    nrpe_compat.add_check(
        shortname=rabbit.RABBIT_USER,
        description='Check RabbitMQ',
        check_cmd='{}/check_rabbitmq.py --user {} --password {} --vhost {}'
                  ''.format(NAGIOS_PLUGINS, user, password, vhost)
    )
    nrpe_compat.write()


@hooks.hook('upgrade-charm')
def upgrade_charm():
    pre_install_hooks()
    add_source(config('source'), config('key'))
    apt_update(fatal=True)

    # Ensure older passwd files in /var/lib/juju are moved to
    # /var/lib/rabbitmq which will end up replicated if clustered
    for f in [f for f in os.listdir('/var/lib/juju')
              if os.path.isfile(os.path.join('/var/lib/juju', f))]:
        if f.endswith('.passwd'):
            s = os.path.join('/var/lib/juju', f)
            d = os.path.join('/var/lib/charm/{}'.format(service_name()), f)

            log('upgrade_charm: Migrating stored passwd'
                ' from %s to %s.' % (s, d))
            shutil.move(s, d)
    rabbit.migrate_passwords_to_peer_relation()

    # explicitly update buggy file name naigos.passwd
    old = os.path.join('var/lib/rabbitmq', 'naigos.passwd')
    if os.path.isfile(old):
        new = os.path.join('var/lib/rabbitmq', 'nagios.passwd')
        shutil.move(old, new)


MAN_PLUGIN = 'rabbitmq_management'


def configure_client_ssl(relation_data):
    """Configure client with ssl
    """
    ssl_mode, external_ca = _get_ssl_mode()
    if ssl_mode == 'off':
        return
    relation_data['ssl_port'] = config('ssl_port')
    if external_ca:
        if config('ssl_ca'):
            relation_data['ssl_ca'] = base64.b64encode(
                config('ssl_ca'))
        return
    ca = ServiceCA.get_ca()
    relation_data['ssl_ca'] = base64.b64encode(ca.get_ca_bundle())


def _get_ssl_mode():
    ssl_mode = config('ssl')
    external_ca = False
    # Legacy config boolean option
    ssl_on = config('ssl_enabled')
    if ssl_mode == 'off' and ssl_on is False:
        ssl_mode = 'off'
    elif ssl_mode == 'off' and ssl_on:
        ssl_mode = 'on'
    ssl_key = config('ssl_key')
    ssl_cert = config('ssl_cert')
    if all((ssl_key, ssl_cert)):
        external_ca = True
    return ssl_mode, external_ca


def _convert_from_base64(v):
    # Rabbit originally supported pem encoded key/cert in config, play
    # nice on upgrades as we now expect base64 encoded key/cert/ca.
    if not v:
        return v
    if v.startswith('-----BEGIN'):
        return v
    try:
        return base64.b64decode(v)
    except TypeError:
        return v


def reconfigure_client_ssl(ssl_enabled=False):
    ssl_config_keys = set(('ssl_key', 'ssl_cert', 'ssl_ca'))
    for rid in relation_ids('amqp'):
        rdata = relation_get(rid=rid, unit=os.environ['JUJU_UNIT_NAME'])
        if not ssl_enabled and ssl_config_keys.intersection(rdata):
            # No clean way to remove entirely, but blank them.
            relation_set(relation_id=rid, ssl_key='', ssl_cert='', ssl_ca='')
        elif ssl_enabled and not ssl_config_keys.intersection(rdata):
            configure_client_ssl(rdata)
            relation_set(relation_id=rid, **rdata)


def configure_rabbit_ssl():
    """
    The legacy config support adds some additional complications.

    ssl_enabled = True, ssl = off -> ssl enabled
    ssl_enabled = False, ssl = on -> ssl enabled
    """
    ssl_mode, external_ca = _get_ssl_mode()

    if ssl_mode == 'off':
        if os.path.exists(rabbit.RABBITMQ_CONF):
            os.remove(rabbit.RABBITMQ_CONF)
        close_port(config('ssl_port'))
        reconfigure_client_ssl()
        return
    ssl_key = _convert_from_base64(config('ssl_key'))
    ssl_cert = _convert_from_base64(config('ssl_cert'))
    ssl_ca = _convert_from_base64(config('ssl_ca'))
    ssl_port = config('ssl_port')

    # If external managed certs then we need all the fields.
    if (ssl_mode in ('on', 'only') and any((ssl_key, ssl_cert)) and
            not all((ssl_key, ssl_cert))):
        log('If ssl_key or ssl_cert are specified both are required.',
            level=ERROR)
        sys.exit(1)

    if not external_ca:
        ssl_cert, ssl_key, ssl_ca = ServiceCA.get_service_cert()

    rabbit.enable_ssl(
        ssl_key, ssl_cert, ssl_port, ssl_ca,
        ssl_only=(ssl_mode == "only"), ssl_client=False)
    reconfigure_client_ssl(True)
    open_port(ssl_port)


def restart_rabbit_update_nrpe():
    service_restart('rabbitmq-server')
    update_nrpe_checks()


@hooks.hook('config-changed')
def config_changed():
    if config('prefer-ipv6'):
        rabbit.assert_charm_supports_ipv6()

    # Add archive source if provided
    add_source(config('source'), config('key'))
    apt_update(fatal=True)
    # Copy in defaults file for updated ulimits
    shutil.copyfile(
        'templates/rabbitmq-server',
        '/etc/default/rabbitmq-server')
    # Install packages to ensure any changes to source
    # result in an upgrade if applicable.
    apt_install(rabbit.PACKAGES, fatal=True)

    open_port(5672)

    chown(RABBIT_DIR, rabbit.RABBIT_USER, rabbit.RABBIT_USER)
    chmod(RABBIT_DIR, 0o775)

    if config('prefer-ipv6'):
        rabbit.bind_ipv6_interface()

    if config('management_plugin') is True:
        rabbit.enable_plugin(MAN_PLUGIN)
        open_port(55672)
    else:
        rabbit.disable_plugin(MAN_PLUGIN)
        close_port(55672)

    configure_rabbit_ssl()

    if is_relation_made("ha"):
        ha_is_active_active = config("ha-vip-only")

        if ha_is_active_active:
            restart_rabbit_update_nrpe()
        else:
            if eligible_leader('res_rabbitmq_vip'):
                restart_rabbit_update_nrpe()
            else:
                log("hacluster relation is present but this node is not active"
                    " skipping update nrpe checks")
    else:
        restart_rabbit_update_nrpe()


def pre_install_hooks():
    for f in glob.glob('exec.d/*/charm-pre-install'):
        if os.path.isfile(f) and os.access(f, os.X_OK):
            subprocess.check_call(['sh', '-c', f])


if __name__ == '__main__':
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
