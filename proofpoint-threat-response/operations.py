""" Copyright start
  MIT License
  Copyright (c) 2024 Fortinet Inc
  Copyright end """

import datetime
import json
import requests

from connectors.core.connector import ConnectorError, get_logger
from requests.auth import HTTPBasicAuth

from const import STATE, CLASSIFICATION, LINK_ATTRIBUTE, SEVERITY

logger = get_logger('proofpoint-threat-response')


def make_api_call(method="GET", endpoint="", config=None, params=None, headers=None, data=None, json_data=None,
                  verify_ssl=False):
    try:
        default_headers = {"Content-Type": "application/json"}
        auth = HTTPBasicAuth(config.get("username"), config.get("password"))
        if headers:
            default_headers.update(headers)
        url = config.get("server_url") + endpoint
        if json_data is None:
            response = requests.request(method=method, auth=auth, url=url, headers=default_headers, data=data,
                                        params=params, verify=verify_ssl)
        else:
            response = requests.request(method=method, auth=auth, url=url, headers=default_headers, data=data,
                                        json=json_data, params=params, verify=verify_ssl)
        if response.ok:
            if response.content:
                response = response.json()
            else:
                response = {"result": "No Data Returned", "status": "success"}
            return response
        else:
            logger.error("Error: {0}".format(response.json()))
            raise ConnectorError('{0}:{1}'.format(response.status_code, response.text))
    except requests.exceptions.SSLError as e:
        logger.exception('{0}'.format(e))
        raise ConnectorError('{0}'.format(e))
    except requests.exceptions.ConnectionError as e:
        logger.exception('{0}'.format(e))
        raise ConnectorError('{0}'.format(e))
    except Exception as e:
        logger.error('{0}'.format(e))
        raise ConnectorError('{0}'.format(e))


def get_list(config, params):
    endpoint = "/api/lists/{list_id}/members.json".format(list_id=params.get("list_id"))
    return make_api_call(config=config, endpoint=endpoint, method="GET")


def add_to_list(config, params):
    json_data = {"member": params.get("indicator")}
    if params.get("description"):
        json_data.update({"description": params.get("description")})
    if params.get("expiration"):
        json_data.update({"expiration": params.get("expiration")})
    endpoint = "/api/lists/{list_id}/members.json".format(list_id=params.get("list_id"))
    return make_api_call(config=config, json_data=json_data, endpoint=endpoint, method="POST")


def block_ip(config, params):
    return add_to_list(config, params)


def block_domain(config, params):
    return add_to_list(config, params)


def block_url(config, params):
    return add_to_list(config, params)


def block_hash(config, params):
    return add_to_list(config, params)


def delete_indicator(config, params):
    endpoint = "/api/lists/{list_id}/members/{indicator_id}.json".format(list_id=params.get("list_id"),
                                                                         indicator_id=params.get("indicator_id"))
    return make_api_call(config=config, endpoint=endpoint, method="DELETE")


def get_incident(config, params):
    query_params = {"expand_events": json.dumps(params.get("expand_events"))}
    endpoint = "/api/incidents/{incident_id}.json".format(incident_id=params.get("incident_id"))
    return make_api_call(config=config, params=query_params, endpoint=endpoint, method="GET")


def search_indicator(config, params):
    indicator_filter = params.get("filter")
    list_indicators = get_list(config, params)
    found_items = []
    for item in list_indicators:
        item_indicator = item.get("host", {}).get("host")
        if item_indicator and indicator_filter in item_indicator:
            found_items.append(item)
    return found_items


def get_incidents(config, params):
    endpoint = "/api/incidents"
    params_data = {"limit": params.get("created_after", 50)}
    all_params = ["state", "created_after", "created_before", "closed_after", "closed_before", "expand_events"]
    for key in all_params:
        update_json(key, params_data, params)
    if params_data.get("state"):
        params_data.update({"state": STATE.get(params.get("state"))})
    return make_api_call(config=config, params=params_data, endpoint=endpoint, method="GET")


def add_comment_to_incident(config, params):
    json_data = {"summary": params.get("comment")}
    if params.get("description"):
        json_data.update({"detail": params.get("description")})
    endpoint = "/api/incidents/{incident_id}/comments.json".format(incident_id=params.get("incident_id"))
    return make_api_call(config=config, json_data=json_data, endpoint=endpoint, method="POST")


def update_comment_to_incident(config, params):
    return add_comment_to_incident(config, params)


def add_user_to_incident(config, params):
    json_data = {"targets": params.get("targets"), "attackers": params.get("attackers")}
    endpoint = "/api/incidents/{incident_id}/users.json".format(incident_id=params.get("incident_id"))
    return make_api_call(config=config, json_data=json_data, endpoint=endpoint, method="POST")


def update_json(key_name, json_data, params):
    if json_data.get(key_name):
        json_data.update({key_name: params.get(key_name)})
    return json_data


def ingest_alert(config, params):
    json_data = {
        "json_version": params.get("json_version")
    }
    all_params = ["expand_events", "post_url_id", "attacker", "classification", "cnc_hosts", "detector", "email",
                  "forensics_hosts", "summary", "target", "threat_info", "custom_fields", "link_attribute",
                  "severity", ]
    for key in all_params:
        update_json(key, json_data, params)
    if json_data.get("classification"):
        json_data["classification"] = CLASSIFICATION.get(json_data.get("classification"))
    if json_data.get("link_attribute"):
        json_data["link_attribute"] = LINK_ATTRIBUTE.get(json_data.get("link_attribute"))
    if json_data.get("severity"):
        json_data["severity"] = LINK_ATTRIBUTE.get(json_data.get("severity"))
    if json_data.get("severity"):
        json_data["severity"] = SEVERITY.get(json_data.get("severity"))
    endpoint = "/threat/json_event/events/{json_source_id}".format(json_source_id=params.get("json_source_id"))
    return make_api_call(config=config, json_data=json_data, endpoint=endpoint, method="POST")


def close_incident(config, params):
    json_data = {"summary": params.get("comment"), "detail": params.get("description")}
    endpoint = "/api/incidents/{incident_id}/close.json".format(incident_id=params.get("incident_id"))
    return make_api_call(config=config, json_data=json_data, endpoint=endpoint, method="POST")


def verify_quarantine(config, params):
    incidents_list = get_incidents(config, params)
    found = {'email': False, 'mid': False, 'quarantine': False}
    resQ = []
    lstAlert = []
    emailTAPtime = params.get("time").timestamp()
    mid = params.get("message_id")
    recipient = params.get("recipient")

    # Collecting emails inside alert to find those with same recipient and messageId
    for incident in incidents_list:
        for alert in incident.get('events'):
            for email in alert.get('emails'):
                if email.get('messageId') == mid and email.get('recipient').get('email') == recipient and email.get(
                        'messageDeliveryTime', {}).get('millis'):
                    found['mid'] = True
                    emailTRAPtimestamp = int(email.get('messageDeliveryTime', {}).get('millis') / 1000)
                    if emailTAPtime == emailTRAPtimestamp:
                        found['email'] = True
                        lstAlert.append({
                            'incidentid': incident.get('id'),
                            'alertid': alert.get('id'),
                            'alerttime': alert.get('received'),
                            'incidenttime': incident.get('created_at'),
                            'messageId': mid,
                            'quarantine_results': incident.get('quarantine_results')
                        })

    quarantineFoundcpt = 0

    # Go though the alert list, and check the quarantine results:
    for alert in lstAlert:
        for quarantine in alert.get('quarantine_results'):
            if quarantine.get('messageId') == mid and quarantine.get('recipient') == recipient:
                found['quarantine'] = True
                tsquarantine = quarantine.get("startTime")
                tsalert = alert.get("alerttime")
                if isinstance(tsquarantine, datetime) and isinstance(tsalert, datetime):
                    diff = (tsquarantine - tsalert).total_seconds()
                    # we want to make sure quarantine starts 2 minuts after creating the alert.
                    if 0 < diff < 120:
                        resQ.append({
                            'quarantine': quarantine,
                            'alert': {
                                'id': alert.get('alertid'),
                                'time': alert.get('alerttime')
                            },
                            'incident': {
                                'id': alert.get('incidentid'),
                                'time': alert.get('incidenttime')
                            }
                        })
                    else:
                        quarantineFoundcpt += 1
                else:
                    logger.debug(f"Failed to parse timestamp of incident: alert={alert} quarantine={quarantine}.")

    if quarantineFoundcpt > 0:
        return {
            "result": f"{mid} Message ID matches to {quarantineFoundcpt} emails quarantined but time alert does not match"}
    if not found['mid']:
        return {"result": f"Message ID {mid} not found in TRAP incidents"}

    midtxt = f'{mid} Message ID found in TRAP alerts,'
    if not found['email']:
        return {
            "result": f"{midtxt} but timestamp between email delivery time and time given as argument doesn't match"}
    elif not found['quarantine']:
        logger.debug("\n".join([json.dumps(alt, indent=4) for alt in lstAlert]))
        return {"result": f"{midtxt} but not in the quarantine list meaning that email has not be quarantined."}
    return {"outputs_prefix": 'ProofPointTRAP.Quarantine', "result": resQ}


def _check_health(config):
    return get_incidents(config, {})


operations_map = {
    'get_list': get_list,
    'add_to_list': add_to_list,
    'block_ip': block_ip,
    'block_domain': block_domain,
    'block_url': block_url,
    'block_hash': block_hash,
    'delete_indicator': delete_indicator,
    'get_incident': get_incident,
    'get_incidents': get_incidents,
    'add_comment_to_incident': add_comment_to_incident,
    'update_comment_to_incident': update_comment_to_incident,
    'add_user_to_incident': add_user_to_incident,
    'ingest_alert': ingest_alert,
    'close_incident': close_incident,
    'search_indicator': search_indicator,
    'verify_quarantine': verify_quarantine
}
