## About the connector
Proofpoint Threat Response is a solution designed to help organizations manage and respond to cybersecurity threats. It provides tools and features to identify, investigate, and remediate security incidents.

This document provides information about the Proofpoint Threat Response Connector, which facilitates automated interactions with a Proofpoint Threat Response server using FortiSOAR playbooks. Add the Proofpoint Threat Response Connector as a step in FortiSOAR playbooks and perform automated operations with Proofpoint Threat Response.

### Version information

Connector Version: 1.0.1

Publisher: Fortinet

Contributor: Ishwari Dubewar

Certified: No

### Release Notes for version 1.0.1
The following enhancements have been made to the Proofpoint Threat Response connector in version 1.0.1:

- Resolved an issue that caused the connector health check to fail.

## Installing the connector
Use the **Content Hub** to install the connector. For the detailed procedure to install a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector).

## Prerequisites to configuring the connector
- You must have the credentials of the Proofpoint Threat Response server to which you will connect and perform automated operations.
- The FortiSOAR server should have outbound connectivity to port 443 on the Proofpoint Threat Response server.

## Minimum Permissions Required
- Not applicable

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector).

### Configuration parameters
In FortiSOAR, on the Connectors page, click the **Proofpoint Threat Response** connector row (if you are in the **Grid** view on the Connectors page) and in the **Configurations** tab enter the required configuration details:

| Parameter | Description |
| --- | --- |
| Server URL | Specify the URL of the Proofpoint Threat Response server to connect and perform automated operations. |
| Username | Specify the username used to access the Proofpoint Threat Response server to connect and perform automated operations. |
| Password | Specify the password used to access the Proofpoint Threat Response server to connect and perform automated operations. |
| Verify SSL | Specifies whether the SSL certificate for the server is to be verified or not. <br>By default, this option is set to True. |

## Actions supported by the connector
The following automated operations can be included in playbooks, and you can also use the annotations to access these operations:

| Function | Description | Annotation and Category |
| --- | --- | --- |
| Get Indicators List | Retrieves all indicators from the specified list. | get_list <br>Investigation |
| Add Indicators | Adds the specified indicators to the specified list. | add_to_list <br>Investigation |
| Block IP Addresses | Blocks the specified IP addresses by adding them to the specified IP address block list. | block_ip <br>Containment |
| Block Domain | Blocks the specified domains by adding them to the specified domain block list. | block_domain <br>Containment |
| Block URL | Blocks the specified URLs by adding them to the specified URL block list. | block_url <br>Containment |
| Block File Hash | Blocks the specified file hashes by adding them to the specified file hash block list. | block_hash <br>Containment |
| Search Indicator | Retrieves indicators from the specified list, based on the filter you have specified. | search_indicator <br>Investigation |
| Delete Indicator | Removes an indicator from Proofpoint Threat Response based on the input parameters you have specified. | delete_indicator <br>Investigation |
| Get Incident By ID | Retrieves the metadata of the specified incident from Proofpoint Threat Response. | get_incident <br>Investigation |
| Get Incidents List | Retrieves metadata for all incidents from Proofpoint Threat Response, based on the filter criteria you have specified, such as the state of the incident or its time of closure. | get_incidents <br>Investigation |
| Add Comment To Incident | Adds a comment to an existing incident in Proofpoint Threat Response, based on the incident ID you have specified. | add_comment_to_incident <br>Investigation |
| Update Comment To Incident | Updates a comment on an existing incident in Proofpoint Threat Response, based on the incident ID you have specified. | update_comment_to_incident <br>Investigation |
| Add User To Incident | Assigns users to the specified incident by designating both the Target and the Attacker. | add_user_to_incident <br>Investigation |
| Ingest Alert | Ingests an alert into Proofpoint Threat Response based on the input parameters you have specified. | ingest_alert <br>Investigation |
| Close Incident | Closes an incident in Proofpoint Threat Response based on the input parameters you have specified. | close_incident <br>Investigation |
| Verify Quarantine | Verifies whether the specified email has been quarantined. | verify_quarantine <br>Investigation |

### operation: Get Indicators List
#### Input parameters

| Parameter | Description |
| --- | --- |
| List ID | Specify the ID of the list whose indicators you want to retrieve. |

#### Output

No output schema is available at this time.

### operation: Add Indicators
#### Input parameters

| Parameter | Description |
| --- | --- |
| List ID | Specify the ID of the list to which you want to add the specified indicators. |
| Indicator | Specify the indicator values to add to the list. Values can be IP addresses, URLs, domains, or file hashes. For example, 192.168.1.1,192.168.1.2. |
| Comment | (Optional) Specify the comment to add with this operation. |
| Expiration | (Optional) Specify the expiration of the indicator. |

#### Output

No output schema is available at this time.

### operation: Block IP Addresses
#### Input parameters

| Parameter | Description |
| --- | --- |
| IP Address | Specify a comma-separated list of IP addresses to add to the block list. |
| Blocklist ID | Specify the ID of the IP address block list. |
| Expiration | (Optional) Specify the date and time at which the specified IP addresses should be removed from the block list. |

#### Output

No output schema is available at this time.

### operation: Block Domain
#### Input parameters

| Parameter | Description |
| --- | --- |
| Domain | Specify a comma-separated list of domains to add to the block list. |
| Blocklist ID | Specify the ID of the domain block list. |
| Expiration | (Optional) Specify the date and time at which the specified domains should be removed from the block list. |

#### Output

No output schema is available at this time.

### operation: Block URL
#### Input parameters

| Parameter | Description |
| --- | --- |
| URL | Specify a comma-separated list of URLs to add to the block list. |
| Blocklist ID | Specify the ID of the URL block list. |
| Expiration | (Optional) Specify the date and time at which the specified URLs should be removed from the block list. |

#### Output

No output schema is available at this time.

### operation: Block File Hash
#### Input parameters

| Parameter | Description |
| --- | --- |
| File Hash | Specify a comma-separated list of file hashes to add to the file hash block list. |
| Blocklist ID | Specify the ID of the file hash block list. |
| Expiration | (Optional) Specify the date and time at which the specified file hashes should be removed from the block list. |

#### Output

No output schema is available at this time.

### operation: Search Indicator
#### Input parameters

| Parameter | Description |
| --- | --- |
| Filter | (Optional) Specify the filter to use for the indicator search. For example, specifying 1.1 returns 1.1.1.1, 22.22.1.1, and 1.1.22.22. |
| Blocklist ID | Specify the ID of the list in which you want to search. |

#### Output

No output schema is available at this time.

### operation: Delete Indicator
#### Input parameters

| Parameter | Description |
| --- | --- |
| List ID | Specify the ID of the list from which you want to delete the specified indicator. |
| Indicator ID | Specify the ID of the indicator that you want to delete from the list. |

#### Output

No output schema is available at this time.

### operation: Get Incident By ID
#### Input parameters

| Parameter | Description |
| --- | --- |
| Incident ID | Specify the ID of the incident whose details you want to retrieve. |
| Expand Events | Select this option to return full event objects in the response. If you clear this option, an array of event IDs is returned instead, which significantly speeds up the response time of the API for incidents that contain a large number of alerts. |

#### Output

No output schema is available at this time.

### operation: Get Incidents List
#### Input parameters

| Parameter | Description |
| --- | --- |
| State | (Optional) Select the state of the incidents that you want to retrieve. You can choose from New, Open, Assigned, Closed, and Ignored. |
| Created After | (Optional) Specify the date and time to retrieve incidents that were created after this date and time. |
| Created Before | (Optional) Specify the date and time to retrieve incidents that were created before this date and time. |
| Closed After | (Optional) Specify the date and time to retrieve incidents that were closed after this date and time. |
| Closed Before | (Optional) Specify the date and time to retrieve incidents that were closed before this date and time. |
| Expand Events | (Optional) Select this option to return full event objects in the response. If you clear this option, an array of event IDs is returned instead, which significantly speeds up the response time of the API for incidents that contain a large number of alerts. |
| Limit | (Optional) Specify the maximum number of incidents that this operation should return. By default, this is set to 50. |

#### Output

No output schema is available at this time.

### operation: Add Comment To Incident
#### Input parameters

| Parameter | Description |
| --- | --- |
| Incident ID | Specify the ID of the incident to which you want to add the comment. |
| Comment | Specify the comment to add to the specified incident. |
| Description | (Optional) Specify the description to add with this operation. |

#### Output

No output schema is available at this time.

### operation: Update Comment To Incident
#### Input parameters

| Parameter | Description |
| --- | --- |
| Incident ID | Specify the ID of the incident whose comment you want to update. |
| Comment | Specify the updated comment. |
| Description | (Optional) Specify the description to add with this operation. |

#### Output

No output schema is available at this time.

### operation: Add User To Incident
#### Input parameters

| Parameter | Description |
| --- | --- |
| Incident ID | Specify the ID of the incident to which you want to add the user. |
| Targets | Specify the list of targets to add to the specified incident. |
| Attackers | Specify the list of attackers to add to the specified incident. |

#### Output

No output schema is available at this time.

### operation: Ingest Alert
#### Input parameters

| Parameter | Description |
| --- | --- |
| JSON Version | Specify the Proofpoint Threat Response JSON version. You can choose from `2.0` and `1.0`. By default, this is set to 2.0. |
| Post URL ID | (Optional) Specify the POST URL of the JSON alert source. You can find this URL by navigating to **Sources** > **JSON event source** > **POST URL**. |
| Attacker | (Optional) Specify an attacker object, in the JSON format: {"attacker": {...}}. The attacker object must contain one of the following keys: `ip_address`, `mac_address`, `host_name`, `url`, or `user`. You can also add the port key to this object. For more information, see the Proofpoint TRAP documentation under JSON Alert Source 2.0. |
| Classification | (Optional) Select the alert classification, which is displayed as Alert Type in the Proofpoint Threat Response UI. You can choose from Malware, Policy Violation, Vulnerability, Network, Spam, Phish, Command and Control, Data Match, Authentication, System Behavior, Impostor, Reported Abuse, and Unknown. |
| CNC Hosts | (Optional) Specify the command and control host information, in the JSON format: {"cnc_hosts": [{"host": "-", "port": "-"}, ...]}. Every item of the cnc_hosts list is in the JSON format. For more information, see the Proofpoint TRAP documentation under JSON Alert Source 2.0. |
| Detector | (Optional) Specify the threat detection tool, such as a firewall or an IPS/IDS system, that generated the original alert, in the JSON format: {"detector": {...}}. For all the relevant JSON fields and for more information, see the Proofpoint TRAP documentation under JSON Alert Source 2.0. |
| Email | (Optional) Specify the email metadata related to the alert, in the JSON format: {"email": {...}}. For all the relevant JSON fields and for more information, see the Proofpoint TRAP documentation under JSON Alert Source 2.0. |
| Forensics Hosts | (Optional) Specify the forensics host information, in the JSON format: {"forensics_hosts": [{"host": "-", "port": "-"}, ...]}. Every item of the forensics_hosts list is in the JSON format. For more information, see the Proofpoint TRAP documentation under JSON Alert Source 2.0. |
| Link Attribute | (Optional) Select the attribute to link to the alerts. You can choose from Target IP Address, Target Hostname, Target Machine Name, Target User, Target Mac Address, Attacker IP Address, Attacker Hostname, Attacker Machine Name, Attacker User, Attacker Mac Address, Email Recipient, Email Sender, Email Subject, Message ID, Threat Filename, and Threat Filehash. |
| Severity | (Optional) Select the severity of the alert. You can choose from Info, Minor, Moderate, Major, Critical, Informational, Low, Medium, and High. |
| Summary | (Optional) Specify the alert summary. This value populates the Alert Details field. |
| Target | (Optional) Specify the target host information, in the JSON format: {"target": {...}}. For all the relevant JSON fields and for more information, see the Proofpoint TRAP documentation under JSON Alert Source 2.0. |
| Threat Info | (Optional) Specify the threat information, in the JSON format: {"threat_info": {...}}. For all the relevant JSON fields and for more information, see the Proofpoint TRAP documentation under JSON Alert Source 2.0. |
| Custom Fields | (Optional) Specify a JSON object for collecting custom name-value pairs as part of the JSON alert sent to Proofpoint Threat Response, in the format: {"custom_fields": {...}}. Although there is no limit to the number of custom fields, Proofpoint recommends keeping this to 10 or fewer fields. For all the relevant JSON fields and for more information, see the Proofpoint TRAP documentation under JSON Alert Source 2.0. |

#### Output

No output schema is available at this time.

### operation: Close Incident
#### Input parameters

| Parameter | Description |
| --- | --- |
| Incident ID | Specify the ID of the incident that you want to close. |
| Comment | Specify the details for the closure notes. |
| Description | Specify the summary for the closure notes. |

#### Output

No output schema is available at this time.

### operation: Verify Quarantine
#### Input parameters

| Parameter | Description |
| --- | --- |
| Message ID | Specify the ID of the email whose quarantine status you want to verify. |
| Time | Specify the delivery time of the email, in the ISO 8601 format. |
| Recipient | Specify the recipient of the email. |

#### Output

No output schema is available at this time.

## Included playbooks
The *`Sample - Proofpoint Threat Response - 1.0.1`* playbook collection comes bundled with the Proofpoint Threat Response connector. These playbooks contain steps using which you can perform all supported actions. You can see the bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR after installing the connector.

- Add Comment To Incident
- Add Indicators
- Add User To Incident
- Block Domain
- Block File Hash
- Block IP Addresses
- Block URL
- Close Incident
- Delete Indicator
- Get Incident By ID
- Get Incidents List
- Get Indicators List
- Ingest Alert
- Search Indicator
- Update Comment To Incident
- Verify Quarantine

> [!Note]
> If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection, since the sample playbook collection gets deleted during connector upgrade and delete.
