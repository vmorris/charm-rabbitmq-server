#!/usr/bin/python

import ceph
import rabbit_utils as rabbit
import utils

import os
import sys
import subprocess

SERVICE_NAME = utils.get_unit_name().replace('-','/').split('/')[0]
POOL_NAME = SERVICE_NAME
RABBIT_DIR='/var/lib/rabbitmq'

def install():
    utils.install(*rabbit.PACKAGES)
    utils.expose(5672)

def amqp_changed():
    l_unit_no=os.getenv('JUJU_UNIT_NAME').split('/')[1]
    r_unit_no=None
    for rid in utils.relation_ids('cluster'):
        for unit in utils.relation_list(rid):
            r_unit_no = unit.split('/')[1]
            if l_unit_no > r_unit_no:
                msg = 'amqp_changed(): Deferring amqp_changed to leader.'
                utils.juju_log('INFO', msg)
                return

    rabbit_user=utils.relation_get('username')
    vhost=utils.relation_get('vhost')
    if None in [rabbit_user, vhost]:
        utils.juju_log('INFO', 'amqp_changed(): Relation not ready.')
        return

    password_file = '/var/lib/juju/%s.passwd' % rabbit_user
    if os.path.exists(password_file):
        password = open(password_file).read().strip()
    else:
        cmd = ['pwgen', '64', '1']
        password = subprocess.check_output(cmd).strip()
        with open(password_file, 'wb') as out:
            out.write(password)

    rabbit.create_vhost(vhost)
    rabbit.create_user(rabbit_user, password)
    rabbit.grant_permissions(rabbit_user, vhost)

    relation_settings = {
        'password': password
    }
    if utils.is_clustered():
        relation_settings['clustered'] = 'true'
        relation_settings['vip'] = utils.config_get('vip')
    utils.relation_set(**relation_settings)


def cluster_joined():
    l_unit_no = os.getenv('JUJU_UNIT_NAME').split('/')[1]
    r_unit_no = os.getenv('JUJU_REMOTE_UNIT').split('/')[1]
    if l_unit_no > r_unit_no:
        utils.juju_log('INFO', 'cluster_joined: Relation greater.')
        return
    rabbit.COOKIE_PATH = '/var/lib/rabbitmq/.erlang.cookie'
    if not os.path.isfile(rabbit.COOKIE_PATH):
        utils.juju_log('ERROR', 'erlang cookie missing from %s' %\
                       rabbit.COOKIE_PATH)
    cookie = open(rabbit.COOKIE_PATH, 'r').read().strip()
    local_hostname = subprocess.check_output(['hostname']).strip()
    utils.relation_set(cookie=cookie, host=local_hostname)


def cluster_changed():
    l_unit_no = os.getenv('JUJU_UNIT_NAME').split('/')[1]
    r_unit_no = os.getenv('JUJU_REMOTE_UNIT').split('/')[1]
    if l_unit_no < r_unit_no:
        utils.juju_log('INFO', 'cluster_joined: Relation lesser.')
        return

    remote_host = utils.relation_get('host')
    cookie = utils.relation_get('cookie')
    if None in [remote_host, cookie]:
        utils.juju_log('INFO',
                       'cluster_joined: remote_host|cookie not yet set.')
        return

    if open(rabbit.COOKIE_PATH, 'r').read().strip() == cookie:
        utils.juju_log('INFO', 'Cookie already synchronized with peer.')
        return

    utils.juju_log('INFO', 'Synchronizing erlang cookie from peer.')
    rabbit.service('stop')
    with open(rabbit.COOKIE_PATH, 'wb') as out:
        out.write(cookie)
    rabbit.service('start')
    rabbit.cluster_with(remote_host)


def ha_joined():
    config = {}
    corosync_bindiface = utils.config_get('ha-bindiface')
    corosync_mcastport = utils.config_get('ha-mcastport')
    vip = utils.config_get('vip')
    vip_iface = utils.config_get('vip_iface')
    vip_cidr = utils.config_get('vip_cidr')
    rbd_name = utils.config_get('rbd-name')

    if None in [corosync_bindiface, corosync_mcastport, vip, vip_iface,
                vip_cidr, rbd_name]:
        utils.juju_log('ERROR', 'Insufficient configuration data to '\
                       'configure hacluster.')
        sys.exit(1)


    if not utils.is_relation_made('ceph'):
        utils.juju_log('INFO',
                       'ha_joined: No ceph relation yet, deferring.')
        return

    relation_settings = {}
    relation_settings['corosync_bindiface'] = corosync_bindiface
    relation_settings['corosync_mcastport'] = corosync_mcastport

    relation_settings['resources'] = {
        'res_rabbitmq_rbd':'ocf:ceph:rbd',
        'res_rabbitmq_fs':'ocf:heartbeat:Filesystem',
        'res_rabbitmq_vip':'ocf:heartbeat:IPaddr2',
        'res_rabbitmq-server':'lsb:rabbitmq-server',
    }

    relation_settings['resource_params'] = {
        'res_rabbitmq_rbd': 'params name="%s" pool="%s" user="%s" secret="%s"' %\
            (rbd_name, POOL_NAME, SERVICE_NAME, ceph.keyfile_path(SERVICE_NAME)),
        'res_rabbitmq_fs': 'params device="/dev/rbd/%s/%s" directory="%s" '\
                        'fstype="ext4" op start start-delay="10s"' %\
            (POOL_NAME, rbd_name, RABBIT_DIR),
        'res_rabbitmq_vip':'params ip="%s" cidr_netmask="%s" nic="%s"' %\
            (vip, vip_cidr, vip_iface),
        'res_rabbitmqd':'op start start-delay="5s" op monitor interval="5s"',
    }

    relation_settings['groups'] = {
        'grp_rabbitmq':'res_rabbitmq_rbd res_rabbitmq_fs res_rabbitmq_vip '\
                       'res_rabbitmq-server',
    }

    for rel_id in utils.relation_ids('ha'):
        utils.relation_set(rid=rel_id, **relation_settings)


def ha_changed():
    if not utils.is_clustered:
        return
    vip = utils.config_get('vip')
    utils.juju_log('INFO', 'ha_changed(): We are now HA clustered. '\
                   'Advertising our VIP (%s) to all AMQP clients.' %\
                   vip)
    relation_settings = {'vip': vip, 'clustered': 'true'}
    for rid in utils.relation_ids('amqp'):
        relation_settings['rid'] = rid
        utils.relation_set(**relation_settings)


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

    if utils.eligible_leader():
        rbd_img = utils.config_get('rbd-name')
        rbd_size = utils.config_get('rbd-size')
        sizemb = int(rbd_size.split('G')[0]) * 1024
        blk_device = '/dev/rbd/%s/%s' % (POOL_NAME, rbd_img)
        ceph.ensure_ceph_storage(service=SERVICE_NAME, pool=POOL_NAME,
                                 rbd_img=rbd_img, sizemb=sizemb,
                                 fstype='ext4', mount_point=RABBIT_DIR,
                                 blk_device=blk_device,
                                 system_services=['rabbitmq-server'])
    else:
        utils.juju_log('INFO',
                       'This is not the peer leader. Not configuring RBD.')
        if utils.running('rabbitmq-server'):
            utils.juju_log('INFO','Stopping rabbitmq-server.')
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

hooks = {
    'install': install,
    'amqp-relation-changed': amqp_changed,
    'cluster-relation-joined': cluster_joined,
    'cluster-relation-changed': cluster_changed,
    'ha-relation-joined': ha_joined,
    'ha-relation-changed': ha_changed,
    'ceph-relation-joined': ceph_joined,
    'ceph-relation-changed': ceph_changed,
}

utils.do_hooks(hooks)
