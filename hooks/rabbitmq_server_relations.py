#!/usr/bin/python

import base64
import json
import os
import shutil
import sys
import subprocess
import glob


import rabbit_utils as rabbit
import lib.utils as utils
import lib.cluster_utils as cluster
import lib.ceph_utils as ceph
import lib.openstack_common as openstack

import _pythonpath
_ = _pythonpath

from charmhelpers.fetch import (
    add_source,
    apt_update)
from charmhelpers.core import hookenv
from charmhelpers.core.host import rsync, mkdir, write_file, pwgen
from charmhelpers.contrib.charmsupport.nrpe import NRPE


SERVICE_NAME = os.getenv('JUJU_UNIT_NAME').split('/')[0]
POOL_NAME = SERVICE_NAME
RABBIT_DIR = '/var/lib/rabbitmq'
NAGIOS_PLUGINS = '/usr/local/lib/nagios/plugins'


def install():
    pre_install_hooks()
    add_source(utils.config_get('source'), utils.config_get('key'))
    apt_update(fatal=True)
    utils.install(*rabbit.PACKAGES)
    utils.expose(5672)
    utils.chown(RABBIT_DIR, rabbit.RABBIT_USER, rabbit.RABBIT_USER)
    utils.chmod(RABBIT_DIR, 0775)


def configure_amqp(username, vhost):
    # get and update service password
    password = None
    cluster_rels = hookenv.relation_ids('cluster')
    if len(cluster_rels)>0:
        cluster_rid = cluster_rels[0]
        password = hookenv.relation_get(attribute='%s.passwd' % username,
                                        rid=cluster_rid,
                                        unit=hookenv.local_unit())
    new_passwd = False
    if not password:
        new_passwd = True
        password = pwgen(length=64)
        if len(cluster_rels)>0:
            # update password in cluster
            hookenv.relation_set(relation_id=cluster_rid,
                                 relation_settings={'%s.passwd' % username: password})

    # refresh password in file
    password_file = os.path.join(RABBIT_DIR, '%s.passwd' % username)
    write_file(password_file, password, rabbit.RABBIT_USER, rabbit.RABBIT_USER, 0660)

    if new_passwd:
        try:
            rabbit.create_vhost(vhost)
        except:
            utils.juju_log('INFO', 'Error creating vhost. It was already created?')

        try:
            rabbit.create_user(username, password)
            rabbit.grant_permissions(username, vhost)
        except:
            utils.juju_log('INFO', 'Error creating rabbit user. It was already created?')
        
    return password


def amqp_changed(relation_id=None, remote_unit=None):
    if cluster.is_clustered() and utils.config_get('ha-vip-only') is False:
        if not cluster.is_leader('res_rabbitmq_vip'):
            msg = 'amqp_changed(): Deferring amqp_changed to eligible_leader.'
            utils.juju_log('INFO', msg)
            return

    relation_settings = {}
    settings = hookenv.relation_get(rid=relation_id, unit=remote_unit)

    singleset = set([
        'username',
        'vhost'])

    if singleset.issubset(settings):
        if None in [settings['username'], settings['vhost']]:
            utils.juju_log('INFO', 'amqp_changed(): Relation not ready.')
            return

        relation_settings['password'] = configure_amqp(username=settings['username'],
                                                       vhost=settings['vhost'])
    else:
        queues = {}
        for k, v in settings.iteritems():
            amqp = k.split('_')[0]
            x = '_'.join(k.split('_')[1:])
            if amqp not in queues:
                queues[amqp] = {}
            queues[amqp][x] = v
        relation_settings = {}
        for amqp in queues:
            if singleset.issubset(queues[amqp]):
                relation_settings['_'.join([amqp, 'password'])] = configure_amqp(queues[amqp]['username'],
                                                                                 queues[amqp]['vhost'])
            
    relation_settings['hostname'] = utils.unit_get('private-address')
    if cluster.is_clustered():
        relation_settings['clustered'] = 'true'
    if utils.is_relation_made('ha'):
        # active/passive settings
        relation_settings['vip'] = utils.config_get('vip')
        relation_settings['ha-vip-only'] = utils.config_get('ha-vip-only')

    if relation_id:
        relation_settings['rid'] = relation_id

    # set if need HA queues or not
    relation_settings['ha_queues'] = (rabbit.compare_version('3.0.1-1'))
    utils.relation_set(**relation_settings)


def cluster_joined():
    if utils.is_relation_made('ha') and \
            utils.config_get('ha-vip-only') is False:
        utils.juju_log('INFO',
                       'hacluster relation is present, skipping native '
                       'rabbitmq cluster config.')
        return

    if utils.is_newer():
        # exit but set the host
        utils.relation_set(slave_host=utils.unit_get('private-address'))
        utils.juju_log('INFO', 'cluster_joined: Relation greater.')
        return
    rabbit.COOKIE_PATH = '/var/lib/rabbitmq/.erlang.cookie'
    if not os.path.isfile(rabbit.COOKIE_PATH):
        utils.juju_log('ERROR', 'erlang cookie missing from %s' %
                       rabbit.COOKIE_PATH)
        return
    cookie = open(rabbit.COOKIE_PATH, 'r').read().strip()

    # add parent host to the relation
    local_hostname = subprocess.check_output(['hostname']).strip()
    utils.relation_set(cookie=cookie, host=local_hostname)


def cluster_changed():
    if utils.is_relation_made('ha') and \
            utils.config_get('ha-vip-only') is False:
        utils.juju_log('INFO',
                       'hacluster relation is present, skipping native '
                       'rabbitmq cluster config.')
        return

    # skip if is parent unit
    if not utils.is_newer():
        return
    cookie = utils.relation_get('cookie')
    if cookie is None:
        utils.juju_log('INFO',
                       'cluster_joined: cookie not yet set.')
        return

    # write passwords to slave unit
    rdata = hookenv.relation_get()
    echo_data = {}
    for attribute, value in rdata.iteritems():
        if '.passwd' in attribute:
            echo_data[attribute] = value
    if len(echo_data) > 0:
        hookenv.relation_set(relation_settings=echo_data)
        for key, value in echo_data.items():
            write_file(rabbit.LIB_PATH+key, value, rabbit.RABBIT_USER, rabbit.RABBIT_USER, 0660)

    # sync cookie
    if open(rabbit.COOKIE_PATH, 'r').read().strip() == cookie:
        utils.juju_log('INFO', 'Cookie already synchronized with peer.')
    else:
        utils.juju_log('INFO', 'Synchronizing erlang cookie from peer.')
        rabbit.service('stop')
        with open(rabbit.COOKIE_PATH, 'wb') as out:
            out.write(cookie)
        rabbit.service('start')

    # cluster with other nodes
    rabbit.cluster_with()


def cluster_departed():
    if utils.is_relation_made('ha') and \
            utils.config_get('ha-vip-only') is False:
        utils.juju_log('INFO',
                       'hacluster relation is present, skipping native '
                       'rabbitmq cluster config.')
        return
    if not utils.is_newer():
        utils.juju_log('INFO', 'cluster_joined: Relation lesser.')
        return
    rabbit.break_cluster()


def ha_joined():
    corosync_bindiface = utils.config_get('ha-bindiface')
    corosync_mcastport = utils.config_get('ha-mcastport')
    vip = utils.config_get('vip')
    vip_iface = utils.config_get('vip_iface')
    vip_cidr = utils.config_get('vip_cidr')
    rbd_name = utils.config_get('rbd-name')
    vip_only = utils.config_get('ha-vip-only')

    if None in [corosync_bindiface, corosync_mcastport, vip, vip_iface,
                vip_cidr, rbd_name] and vip_only is False:
        utils.juju_log('ERROR', 'Insufficient configuration data to '
                       'configure hacluster.')
        sys.exit(1)
    elif None in [corosync_bindiface, corosync_mcastport, vip, vip_iface,
                  vip_cidr] and vip_only is True:
        utils.juju_log('ERROR', 'Insufficient configuration data to '
                       'configure VIP-only hacluster.')
        sys.exit(1)

    if not utils.is_relation_made('ceph', 'auth') and vip_only is False:
        utils.juju_log('INFO',
                       'ha_joined: No ceph relation yet, deferring.')
        return

    name = '%s@localhost' % SERVICE_NAME
    if rabbit.get_node_name() != name and vip_only is False:
        utils.juju_log('INFO', 'Stopping rabbitmq-server.')
        utils.stop('rabbitmq-server')
        rabbit.set_node_name('%s@localhost' % SERVICE_NAME)
    else:
        utils.juju_log('INFO', 'Node name already set to %s.' % name)

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
        relation_settings['groups'] = {
            'grp_rabbitmq': 'res_rabbitmq_rbd res_rabbitmq_fs res_rabbitmq_vip '
                            'res_rabbitmq-server',
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
                                 SERVICE_NAME, ceph.keyfile_path(SERVICE_NAME)),
            'res_rabbitmq_fs': 'params device="/dev/rbd/%s/%s" directory="%s" '
                               'fstype="ext4" op start start-delay="10s"' %
                               (POOL_NAME, rbd_name, RABBIT_DIR),
            'res_rabbitmq_vip': 'params ip="%s" cidr_netmask="%s" nic="%s"' %
                                (vip, vip_cidr, vip_iface),
            'res_rabbitmq-server': 'op start start-delay="5s" '
                                   'op monitor interval="5s"',
        }

        relation_settings['groups'] = {
            'grp_rabbitmq': 'res_rabbitmq_rbd res_rabbitmq_fs res_rabbitmq_vip '
                            'res_rabbitmq-server',
        }

    for rel_id in utils.relation_ids('ha'):
        utils.relation_set(rid=rel_id, **relation_settings)

    env_vars = {
        'OPENSTACK_PORT_EPMD': 4369,
        'OPENSTACK_PORT_MCASTPORT': utils.config_get('ha-mcastport'),
    }
    openstack.save_script_rc(**env_vars)


def ha_changed():
    if not cluster.is_clustered():
        return
    vip = utils.config_get('vip')
    utils.juju_log('INFO', 'ha_changed(): We are now HA clustered. '
                   'Advertising our VIP (%s) to all AMQP clients.' %
                   vip)
    if utils.config_get('ha-vip-only') is False:
        # need to re-authenticate all clients since node-name changed.
        for rid in utils.relation_ids('amqp'):
            for unit in utils.relation_list(rid):
                amqp_changed(relation_id=rid, remote_unit=unit)


def ceph_joined():
    utils.juju_log('INFO', 'Start Ceph Relation Joined')
    ceph.install()
    utils.juju_log('INFO', 'Finish Ceph Relation Joined')


def ceph_changed():
    utils.juju_log('INFO', 'Start Ceph Relation Changed')
    auth = utils.relation_get('auth')
    key = utils.relation_get('key')
    if None in [auth, key]:
        utils.juju_log('INFO', 'Missing key or auth in relation')
        sys.exit(0)

    ceph.configure(service=SERVICE_NAME, key=key, auth=auth)

    if cluster.eligible_leader('res_rabbitmq_vip'):
        rbd_img = utils.config_get('rbd-name')
        rbd_size = utils.config_get('rbd-size')
        sizemb = int(rbd_size.split('G')[0]) * 1024
        blk_device = '/dev/rbd/%s/%s' % (POOL_NAME, rbd_img)
        rbd_pool_rep_count = utils.config_get('ceph-osd-replication-count')
        ceph.ensure_ceph_storage(service=SERVICE_NAME, pool=POOL_NAME,
                                 rbd_img=rbd_img, sizemb=sizemb,
                                 fstype='ext4', mount_point=RABBIT_DIR,
                                 blk_device=blk_device,
                                 system_services=['rabbitmq-server'],
                                 rbd_pool_replicas=rbd_pool_rep_count)
    else:
        utils.juju_log('INFO',
                       'This is not the peer leader. Not configuring RBD.')
        utils.juju_log('INFO', 'Stopping rabbitmq-server.')
        utils.stop('rabbitmq-server')

    # If 'ha' relation has been made before the 'ceph' relation
    # it is important to make sure the ha-relation data is being
    # sent.
    if utils.is_relation_made('ha'):
        utils.juju_log('INFO', '*ha* relation exists. Triggering ha_joined()')
        ha_joined()
    else:
        utils.juju_log('INFO', '*ha* relation does not exist.')
    utils.juju_log('INFO', 'Finish Ceph Relation Changed')


def update_nrpe_checks():
    if os.path.isdir(NAGIOS_PLUGINS):
        rsync(os.path.join(os.getenv('CHARM_DIR'), 'scripts',
                           'check_rabbitmq.py'),
              os.path.join(NAGIOS_PLUGINS, 'check_rabbitmq.py'))

    # create unique user and vhost for each unit
    current_unit = hookenv.local_unit().replace('/', '-')
    user = 'nagios-%s' % current_unit
    vhost = 'nagios-%s' % current_unit
    password_file = os.path.join(RABBIT_DIR, '%s.passwd' % user)
    if os.path.exists(password_file):
        password = open(password_file).read().strip()
        utils.chmod(password_file, 0660)
        utils.chown(password_file, rabbit.RABBIT_USER, rabbit.RABBIT_USER)
    else:
        cmd = ['pwgen', '64', '1']
        password = subprocess.check_output(cmd).strip()
        write_file(password_file, password, rabbit.RABBIT_USER, rabbit.RABBIT_USER, 0660)

    rabbit.create_vhost(vhost)
    rabbit.create_user(user, password)
    rabbit.grant_permissions(user, vhost)

    nrpe_compat = NRPE()
    nrpe_compat.add_check(
        shortname=rabbit.RABBIT_USER,
        description='Check RabbitMQ',
        check_cmd='{}/check_rabbitmq.py --user {} --password {} --vhost {}'
                  ''.format(NAGIOS_PLUGINS, user, password, vhost)
    )
    nrpe_compat.write()


def upgrade_charm():
    pre_install_hooks()
    add_source(utils.config_get('source'), utils.config_get('key'))
    apt_update(fatal=True)

    cluster_rid = None
    cluster_rels = hookenv.relation_ids('cluster')
    if len(cluster_rels)>0:
        cluster_rid = cluster_rels[0]

    # Ensure older passwd files in /var/lib/juju are moved to
    # /var/lib/rabbitmq which will end up replicated if clustered.
    for f in [f for f in os.listdir('/var/lib/juju')
              if os.path.isfile(os.path.join('/var/lib/juju', f))]:
        if f.endswith('.passwd'):
            s = os.path.join('/var/lib/juju', f)
            d = os.path.join('/var/lib/rabbitmq', f)

            # propagate to cluster if needed
            if cluster_rid:
                username = os.path.basename(s)
                password = hookenv.relation_get(attribute=username, rid=cluster_rid,
                                                unit=hookenv.local_unit())
                if password is None:
                    with open(s, 'r') as h:
                        stored_password = h.read()
                    if stored_password:
                        hookenv.relation_set(relation_id=cluster_rid,
                                             relation_settings={username: stored_password})

            utils.juju_log('INFO',
                           'upgrade_charm: Migrating stored passwd'
                           ' from %s to %s.' % (s, d))
            shutil.move(s, d)

    # explicitly update buggy file name naigos.passwd
    old = os.path.join('var/lib/rabbitmq', 'naigos.passwd')
    if os.path.isfile(old):
        new = os.path.join('var/lib/rabbitmq', 'nagios.passwd')
        shutil.move(old, new)


MAN_PLUGIN = 'rabbitmq_management'


def config_changed():
    if utils.config_get('management_plugin') is True:
        rabbit.enable_plugin(MAN_PLUGIN)
        utils.open_port(55672)
    else:
        rabbit.disable_plugin(MAN_PLUGIN)
        utils.close_port(55672)

    if utils.config_get('ssl_enabled') is True:
        ssl_key = utils.config_get('ssl_key')
        ssl_cert = utils.config_get('ssl_cert')
        ssl_port = utils.config_get('ssl_port')
        if None in [ssl_key, ssl_cert, ssl_port]:
            utils.juju_log('ERROR',
                           'Please provide ssl_key, ssl_cert and ssl_port'
                           ' config when enabling SSL support')
            sys.exit(1)
        else:
            rabbit.enable_ssl(ssl_key, ssl_cert, ssl_port)
            utils.open_port(ssl_port)
    else:
        if os.path.exists(rabbit.RABBITMQ_CONF):
            os.remove(rabbit.RABBITMQ_CONF)
        utils.close_port(utils.config_get('ssl_port'))

    if cluster.eligible_leader('res_rabbitmq_vip') or \
       utils.config_get('ha-vip-only') is True:
        utils.restart('rabbitmq-server')

    update_nrpe_checks()


def pre_install_hooks():
    for f in glob.glob('exec.d/*/charm-pre-install'):
        if os.path.isfile(f) and os.access(f, os.X_OK):
            subprocess.check_call(['sh', '-c', f])

hooks = {
    'install': install,
    'amqp-relation-changed': amqp_changed,
    'cluster-relation-joined': cluster_joined,
    'cluster-relation-changed': cluster_changed,
    'cluster-relation-departed': cluster_departed,
    'ha-relation-joined': ha_joined,
    'ha-relation-changed': ha_changed,
    'ceph-relation-joined': ceph_joined,
    'ceph-relation-changed': ceph_changed,
    'upgrade-charm': upgrade_charm,
    'config-changed': config_changed,
    'nrpe-external-master-relation-changed': update_nrpe_checks
}

utils.do_hooks(hooks)
