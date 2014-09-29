import os
from testtools import TestCase
from mock import patch, MagicMock

os.environ['JUJU_UNIT_NAME'] = 'UNIT_TEST/0'
import rabbitmq_server_relations


class RelationUtil(TestCase):
    def setUp(self):
        self.fake_repo = {}
        super(RelationUtil, self).setUp()

    def _apt_cache(self):
        """Used for mocking out apt_pkg.Cache"""
        # mocks out the apt cache
        def cache_get(package):
            pkg = MagicMock()
            if package in self.fake_repo \
                    and 'pkg_vers' in self.fake_repo[package]:
                pkg.name = package
                pkg.current_ver.ver_str = self.fake_repo[package]['pkg_vers']
            elif (package in self.fake_repo and
                  'pkg_vers' not in self.fake_repo[package]):
                pkg.name = package
                pkg.current_ver = None
            else:
                raise KeyError
            return pkg
        cache = MagicMock()
        cache.__getitem__.side_effect = cache_get
        return cache

    @patch('rabbitmq_server_relations.get_ipv6_addr')
    @patch('rabbitmq_server_relations.config')
    @patch('rabbitmq_server_relations.relation_set')
    @patch('apt_pkg.Cache')
    @patch('rabbitmq_server_relations.is_clustered')
    @patch('rabbitmq_server_relations.configure_client_ssl')
    @patch('rabbitmq_server_relations.relation_get')
    @patch('rabbitmq_server_relations.eligible_leader')
    def test_amqp_changed_compare_versions_ha_queues(
            self,
            eligible_leader, relation_get, configure_client_ssl,
            is_clustered, apt_cache, relation_set, mock_config,
            mock_get_ipv6_addr):
        """
        Compare version above and below 3.0.1.
        Make sure ha_queues is set correctly on each side.
        """
        mock_get_ipv6_addr.return_value = ['oo.la.la']
        eligible_leader.return_value = True
        relation_get.return_value = {}
        is_clustered.return_value = False
        apt_cache.return_value = self._apt_cache()

        self.fake_repo = {'rabbitmq-server': {'pkg_vers': '3.0'}}
        rabbitmq_server_relations.amqp_changed(None, None)
        relation_set.assert_called_with(
            relation_settings={'private-address': 'oo.la.la',
                               'ha_queues': True})

        self.fake_repo = {'rabbitmq-server': {'pkg_vers': '3.0.2'}}
        rabbitmq_server_relations.amqp_changed(None, None)
        relation_set.assert_called_with(
            relation_settings={'private-address': 'oo.la.la'})
