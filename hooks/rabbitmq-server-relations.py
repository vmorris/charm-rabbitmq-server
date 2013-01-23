#!/usr/bin/python

import rabbit_utils as rabbit
import utils

import os
import sys
import subprocess

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
    if None in [corosync_bindiface, corosync_mcastport, vip, vip_iface,
                vip_cidr]:
        utils.juju_log('ERROR', 'Insufficient configuration data to '\
                       'configure hacluster.')
        sys.exit(1)

    relation_settings = {}
    relation_settings['corosync_bindiface'] = corosync_bindiface
    relation_settings['corosync_mcastport'] = corosync_mcastport
    relation_settings['resources'] = {
        'res_rabbitmq_vip': 'ocf:heartbeat:IPaddr2'
    }
    relation_settings['resource_params'] = {
        'res_rabbitmq_vip': ('params ip="%s" cider_netmask="%s" nic="%s"' %\
                             (vip, vip_cidr, vip_iface))
    }
    utils.relation_set(**relation_settings)


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


hooks = {
    'install': install,
    'amqp-relation-changed': amqp_changed,
    'cluster-relation-joined': cluster_joined,
    'cluster-relation-changed': cluster_changed,
    'ha-relation-joined': ha_joined,
    'ha-relation-changed': ha_changed,
}

utils.do_hooks(hooks)
