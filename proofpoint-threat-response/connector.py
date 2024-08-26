""" Copyright start
  MIT License
  Copyright (c) 2024 Fortinet Inc
  Copyright end """


from connectors.core.connector import Connector, ConnectorError, get_logger
from .operations import operations_map, _check_health

logger = get_logger('proofpoint-threat-response')


class PROOFPOINT_THREAT_RESPONSE(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations_map.get(operation)
        return action(config, params)

    def check_health(self, config):
        logger.info('starting health check')
        _check_health(config)
        logger.info('Completed health check and no errors found')
        