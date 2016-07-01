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

import mock
import os
import unittest
import tempfile
import sys
import collections
from functools import wraps


with mock.patch('charmhelpers.core.hookenv.cached') as cached:
    def passthrough(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._wrapped = func
        return wrapper
    cached.side_effect = passthrough
    import rabbit_utils

sys.modules['MySQLdb'] = mock.Mock()


class ConfigRendererTests(unittest.TestCase):

    class FakeContext(object):
        def __call__(self, *a, **k):
            return {'foo': 'bar'}

    config_map = collections.OrderedDict(
        [('/this/is/a/config', {
            'hook_contexts': [
                FakeContext()
            ]
        })]
    )

    def setUp(self):
        super(ConfigRendererTests, self).setUp()
        self.renderer = rabbit_utils.ConfigRenderer(
            self.config_map)

    def test_has_config_data(self):
        self.assertTrue(
            '/this/is/a/config' in self.renderer.config_data.keys())

    @mock.patch("rabbit_utils.log")
    @mock.patch("rabbit_utils.render")
    def test_write_all(self, log, render):
        self.renderer.write_all()

        self.assertTrue(render.called)
        self.assertTrue(log.called)


RABBITMQCTL_CLUSTERSTATUS_RUNNING = """Cluster status of node 'rabbit@juju-devel3-machine-19' ...
[{nodes,[{disc,['rabbit@juju-devel3-machine-14',
                'rabbit@juju-devel3-machine-19']}]},
 {running_nodes,['rabbit@juju-devel3-machine-14',
                 'rabbit@juju-devel3-machine-19']},
 {cluster_name,<<"rabbit@juju-devel3-machine-14.openstacklocal">>},
 {partitions,[]}]
 """

RABBITMQCTL_CLUSTERSTATUS_SOLO = """Cluster status of node 'rabbit@juju-devel3-machine-14' ...
[{nodes,[{disc,['rabbit@juju-devel3-machine-14']}]},
 {running_nodes,['rabbit@juju-devel3-machine-14']},
 {cluster_name,<<"rabbit@juju-devel3-machine-14.openstacklocal">>},
 {partitions,[]}]
 """


class UtilsTests(unittest.TestCase):
    def setUp(self):
        super(UtilsTests, self).setUp()

    @mock.patch("rabbit_utils.log")
    def test_update_empty_hosts_file(self, mock_log):
        map = {'1.2.3.4': 'my-host'}
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            rabbit_utils.HOSTS_FILE = tmpfile.name
            rabbit_utils.HOSTS_FILE = tmpfile.name
            rabbit_utils.update_hosts_file(map)

        with open(tmpfile.name, 'r') as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], "%s %s\n" % (map.items()[0]))

    @mock.patch("rabbit_utils.log")
    def test_update_hosts_file_w_dup(self, mock_log):
        map = {'1.2.3.4': 'my-host'}
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            rabbit_utils.HOSTS_FILE = tmpfile.name

            with open(tmpfile.name, 'w') as fd:
                fd.write("%s %s\n" % (map.items()[0]))

            rabbit_utils.update_hosts_file(map)

        with open(tmpfile.name, 'r') as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], "%s %s\n" % (map.items()[0]))

    @mock.patch("rabbit_utils.log")
    def test_update_hosts_file_entry(self, mock_log):
        altmap = {'1.1.1.1': 'alt-host'}
        map = {'1.1.1.1': 'hostA',
               '2.2.2.2': 'hostB',
               '3.3.3.3': 'hostC',
               '4.4.4.4': 'hostD'}
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            rabbit_utils.HOSTS_FILE = tmpfile.name

            with open(tmpfile.name, 'w') as fd:
                fd.write("#somedata\n")
                fd.write("%s %s\n" % (altmap.items()[0]))

            rabbit_utils.update_hosts_file(map)

        with open(rabbit_utils.HOSTS_FILE, 'r') as fd:
            lines = fd.readlines()

        os.remove(tmpfile.name)
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], "#somedata\n")
        self.assertEqual(lines[1], "%s %s\n" % (map.items()[0]))
        self.assertEqual(lines[4], "%s %s\n" % (map.items()[3]))

    @mock.patch('rabbit_utils.running_nodes')
    def test_not_clustered(self, mock_running_nodes):
        print "test_not_clustered"
        mock_running_nodes.return_value = []
        self.assertFalse(rabbit_utils.clustered())

    @mock.patch('rabbit_utils.running_nodes')
    def test_clustered(self, mock_running_nodes):
        mock_running_nodes.return_value = ['a', 'b']
        self.assertTrue(rabbit_utils.clustered())

    @mock.patch('rabbit_utils.subprocess')
    def test_running_nodes(self, mock_subprocess):
        '''Ensure cluster_status can be parsed for a clustered deployment'''
        mock_subprocess.check_output.return_value = \
            RABBITMQCTL_CLUSTERSTATUS_RUNNING
        self.assertEqual(rabbit_utils.running_nodes(),
                         ['rabbit@juju-devel3-machine-14',
                          'rabbit@juju-devel3-machine-19'])

    @mock.patch('rabbit_utils.subprocess')
    def test_running_nodes_solo(self, mock_subprocess):
        '''Ensure cluster_status can be parsed for a single unit deployment'''
        mock_subprocess.check_output.return_value = \
            RABBITMQCTL_CLUSTERSTATUS_SOLO
        self.assertEqual(rabbit_utils.running_nodes(),
                         ['rabbit@juju-devel3-machine-14'])

    @mock.patch('rabbit_utils.peer_retrieve')
    def test_leader_node(self, mock_peer_retrieve):
        mock_peer_retrieve.return_value = 'juju-devel3-machine-15'
        self.assertEqual(rabbit_utils.leader_node(),
                         'rabbit@juju-devel3-machine-15')
        mock_peer_retrieve.assert_called_with('leader_nodename')

    @mock.patch('rabbit_utils.relation_set')
    @mock.patch('rabbit_utils.get_local_nodename')
    @mock.patch('rabbit_utils.wait_app')
    @mock.patch('rabbit_utils.subprocess.check_call')
    @mock.patch('rabbit_utils.subprocess.check_output')
    @mock.patch('rabbit_utils.time')
    @mock.patch('rabbit_utils.running_nodes')
    @mock.patch('rabbit_utils.leader_node')
    @mock.patch('rabbit_utils.clustered')
    @mock.patch('rabbit_utils.cmp_pkgrevno')
    def test_cluster_with_not_clustered(self, mock_cmp_pkgrevno,
                                        mock_clustered, mock_leader_node,
                                        mock_running_nodes, mock_time,
                                        mock_check_output, mock_check_call,
                                        mock_wait_app, mock_get_local_nodename,
                                        mock_relation_set):
        mock_cmp_pkgrevno.return_value = True
        mock_clustered.return_value = False
        mock_leader_node.return_value = 'rabbit@juju-devel7-machine-11'
        mock_running_nodes.return_value = ['rabbit@juju-devel5-machine-19']
        rabbit_utils.cluster_with()
        mock_check_output.assert_called_with([rabbit_utils.RABBITMQ_CTL,
                                              'join_cluster',
                                              'rabbit@juju-devel7-machine-11'],
                                             stderr=-2)

    @mock.patch('rabbit_utils.subprocess.check_call')
    @mock.patch('rabbit_utils.subprocess.check_output')
    @mock.patch('rabbit_utils.time')
    @mock.patch('rabbit_utils.running_nodes')
    @mock.patch('rabbit_utils.leader_node')
    @mock.patch('rabbit_utils.clustered')
    @mock.patch('rabbit_utils.cmp_pkgrevno')
    def test_cluster_with_clustered(self, mock_cmp_pkgrevno, mock_clustered,
                                    mock_leader_node, mock_running_nodes,
                                    mock_time, mock_check_output,
                                    mock_check_call):
        mock_clustered.return_value = True
        mock_leader_node.return_value = 'rabbit@juju-devel7-machine-11'
        mock_running_nodes.return_value = ['rabbit@juju-devel5-machine-19',
                                           'rabbit@juju-devel7-machine-11']
        rabbit_utils.cluster_with()
        self.assertEqual(0, mock_check_output.call_count)

    @mock.patch('rabbit_utils.wait_app')
    @mock.patch('rabbit_utils.subprocess.check_call')
    @mock.patch('rabbit_utils.subprocess.check_output')
    @mock.patch('rabbit_utils.time')
    @mock.patch('rabbit_utils.running_nodes')
    @mock.patch('rabbit_utils.leader_node')
    @mock.patch('rabbit_utils.clustered')
    @mock.patch('rabbit_utils.cmp_pkgrevno')
    def test_cluster_with_no_leader(self, mock_cmp_pkgrevno, mock_clustered,
                                    mock_leader_node, mock_running_nodes,
                                    mock_time, mock_check_output,
                                    mock_check_call, mock_wait_app):
        mock_clustered.return_value = False
        mock_leader_node.return_value = None
        mock_running_nodes.return_value = ['rabbit@juju-devel5-machine-19']
        rabbit_utils.cluster_with()
        self.assertEqual(0, mock_check_output.call_count)

    def test_assess_status(self):
        with mock.patch.object(rabbit_utils, 'assess_status_func') as asf:
            callee = mock.MagicMock()
            asf.return_value = callee
            rabbit_utils.assess_status('test-config')
            asf.assert_called_once_with('test-config')
            callee.assert_called_once_with()

    @mock.patch.object(rabbit_utils, 'clustered')
    @mock.patch.object(rabbit_utils, 'status_set')
    @mock.patch.object(rabbit_utils, 'assess_cluster_status')
    @mock.patch.object(rabbit_utils, 'services')
    @mock.patch.object(rabbit_utils, '_determine_os_workload_status')
    def test_assess_status_func(self,
                                _determine_os_workload_status,
                                services,
                                assess_cluster_status,
                                status_set,
                                clustered):
        services.return_value = 's1'
        _determine_os_workload_status.return_value = ('active', '')
        clustered.return_value = True
        rabbit_utils.assess_status_func('test-config')()
        # ports=None whilst port checks are disabled.
        _determine_os_workload_status.assert_called_once_with(
            'test-config', {}, charm_func=assess_cluster_status, services='s1',
            ports=None)
        status_set.assert_called_once_with('active',
                                           'Unit is ready and clustered')

    def test_pause_unit_helper(self):
        with mock.patch.object(rabbit_utils, '_pause_resume_helper') as prh:
            rabbit_utils.pause_unit_helper('random-config')
            prh.assert_called_once_with(
                rabbit_utils.pause_unit,
                'random-config')
        with mock.patch.object(rabbit_utils, '_pause_resume_helper') as prh:
            rabbit_utils.resume_unit_helper('random-config')
            prh.assert_called_once_with(
                rabbit_utils.resume_unit,
                'random-config')

    @mock.patch.object(rabbit_utils, 'services')
    def test_pause_resume_helper(self, services):
        f = mock.MagicMock()
        services.return_value = 's1'
        with mock.patch.object(rabbit_utils, 'assess_status_func') as asf:
            asf.return_value = 'assessor'
            rabbit_utils._pause_resume_helper(f, 'some-config')
            asf.assert_called_once_with('some-config')
            # ports=None whilst port checks are disabled.
            f.assert_called_once_with('assessor', services='s1', ports=None)
