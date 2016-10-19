#!/usr/bin/env python3
# Copyright (C) 2016  Red Hat, Inc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Commissaire HTTP based application server.
"""
from oslo_config import cfg
import argparse
import importlib
from oslo_log import log as logging

from commissaire_http.server.routing import DISPATCHER
from commissaire_http import CommissaireHttpServer, parse_args


CONF = cfg.CONF

#
# # TODO: Make this configurable
# for name in (
#         'Dispatcher', 'Router', 'Bus', 'CommissaireHttpServer', 'Handlers'):
#     logger = logging.getLogger(name)
#     logger.setLevel(logging.DEBUG)
#     handler = logging.StreamHandler()
#     handler.setFormatter(logging.Formatter(
#         '%(name)s(%(levelname)s): %(message)s'))
#     logger.handlers.append(handler)
# # --


def inject_authentication(plugin, kwargs):
    """
    Injects authentication into the dispatcher's dispatch method.

    :param plugin: Name of the Authenticator plugin.
    :type plugin: str
    :param kwargs: Arguments for the Authenticator
    :type kwargs: dict or list
    :returns: A wrapped Dispatcher instance
    :rtype: commissaire.dispatcher.Dispatcher
    """
    module = importlib.import_module(plugin)
    authentication_class = getattr(module, 'AuthenticationPlugin')

    authentication_kwargs = {}
    if type(kwargs) is str:
        if '=' in kwargs:
            for item in kwargs.split(','):
                key, value = item.split('=')
                authentication_kwargs[key.strip()] = value.strip()
    elif type(kwargs) is dict:
        # _read_config_file() sets this up.
        authentication_kwargs = kwargs

    # NOTE: We wrap only the dispatch method, not the entire
    #       dispatcher instance.
    DISPATCHER.dispatch = authentication_class(
        DISPATCHER.dispatch, **authentication_kwargs)
    return DISPATCHER


def main():
    """
    Main entry point.
    """
    listen_group = cfg.OptGroup(name='listen',
                                title='Listen options')
    listen_opts = [
        cfg.IPOpt('interface',
                   default='0.0.0.0',
                   help='Interface to listen on'),
        cfg.PortOpt('port',
                default=8000,
                help='Port to listen on')
    ]
    CONF.register_group(listen_group)
    CONF.register_cli_opts(listen_opts, group='listen')


    tls_group = cfg.OptGroup(name='tls',
                                title='TLS options')
    tls_opts = [
        cfg.StrOpt('pemfile',
                help='Full path to the TLS PEM for the commissaire server'),
        cfg.PortOpt('clientverifyfile',
                help=('Full path to the TLS file containing the certificate '
                     'authorities that client certificates should be verified against'))
    ]
    CONF.register_group(tls_group)
    CONF.register_cli_opts(tls_opts, group='tls')


    auth_group = cfg.OptGroup(name='authentication',
                                title='Authentication options')
    auth_opts = [
        cfg.StrOpt('plugin',
                default='commissaire_http.authentication.httpbasicauth',
                metavar='MODULE_NAME',
                help='Full path to the TLS PEM for the commissaire server'),
        cfg.StrOpt('plugin-kwargs',
                default='filepath=/etc/commissaire/users.json',
                metavar='KEYWORD_ARGS',
                help='Authentication Plugin configuration (key=value,...)')
    ]
    CONF.register_group(auth_group)
    CONF.register_cli_opts(auth_opts, group='authentication')

    bus_group = cfg.OptGroup(name='bus',
                                title='Bus options')
    bus_opts = [
        cfg.StrOpt('exchange',
                   default='commissaire',
                   help='Bus Topic Name'),
        cfg.URIOpt('uri',
                default='redis://127.0.0.1:6379/',
                help='Bus Connection URI')
    ]

    CONF.register_group(bus_group)
    CONF.register_cli_opts(bus_opts, group='bus')

    logging.register_options(cfg.CONF)
    cfg.CONF(project='commissaire',
             prog='commissaire-server',
             version='dev')
    logging.setup(cfg.CONF, 'commissaire-server')
    logging.set_defaults()
    logger = logging.getLogger(__name__)

    if CONF.debug:
        CONF.log_opt_values(logger, logging.DEBUG)


    try:
        DISPATCHER = inject_authentication(
                CONF.authentication.plugin, CONF.authentication.plugin_kwargs)

        # Create the server
        server = CommissaireHttpServer(
            CONF.listen.interface,
            CONF.listen.port,
            DISPATCHER,
            CONF.tls.pemfile,
            CONF.tls.clientverifyfile)

        # Set up our bus data
        server.setup_bus(
            CONF.bus.exchange,
            CONF.bus.uri,
            [{'name': 'simple', 'routing_key': 'simple.*'}])

        # Serve until we are killed off
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    except ImportError:
        logger.error('Could not import "{}" for authentication'.format(
            args.authentication_plugin))
    except Exception as error:  # pragma: no cover
        from traceback import print_exc
        print_exc()
        logger.error('Exception shown above. Error: {}'.format(error))


if __name__ == '__main__':  # pragma: no cover
    main()
