## About the connector
Proofpoint Threat Response is a solution designed to help organizations manage and respond to cybersecurity threats. It provides tools and features to identify, investigate, and remediate security incidents.
<p>This document provides information about the Proofpoint Threat Response Connector, which facilitates automated interactions, with a Proofpoint Threat Response server using FortiSOAR&trade; playbooks. Add the Proofpoint Threat Response Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with Proofpoint Threat Response.</p>

### Version information

Connector Version: 1.0.0


Authored By: Fortinet

Certified: No
## Installing the connector
<p>Use the <strong>Content Hub</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.</p><p>You can also use the <code>yum</code> command as a root user to install the connector:</p>
<pre>yum install cyops-connector-proofpoint-threat-response</pre>

## Prerequisites to configuring the connector
- You must have the credentials of Proofpoint Threat Response server to which you will connect and perform automated operations.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the Proofpoint Threat Response server.

## Minimum Permissions Required
- Not applicable

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>Proofpoint Threat Response</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations</strong> tab enter the required configuration details:</p>
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Server URL</td><td>Specify the URL of the Proofpoint Threat Response server to connect and perform automated operations.
</td>
</tr><tr><td>Username</td><td>Specify the Username used to access the Proofpoint Threat Response server to connect and perform automated operations.
</td>
</tr><tr><td>Password</td><td>Specify the Password used to access the Proofpoint Threat Response server to connect and perform automated operations.
</td>
</tr><tr><td>Verify SSL</td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set to True.</td></tr>
</tbody></table>
## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Get Indicators List</td><td>Retrieves all indicators from the specified list.</td><td>get_list <br/>Investigation</td></tr>
<tr><td>Add Indicators</td><td>Add indicators to the specified list.</td><td>add_to_list <br/>Investigation</td></tr>
<tr><td>Block IP Addresses</td><td>Block the supplied IP Addresses in to the specified IP Addresses block list.</td><td>block_ip <br/>Containment</td></tr>
<tr><td>Block Domain</td><td>Block the supplied domains to the specified domains block list.</td><td>block_domain <br/>Containment</td></tr>
<tr><td>Block URL</td><td>Block the supplied URLs to the specified URLs block list.</td><td>block_url <br/>Containment</td></tr>
<tr><td>Block File Hash</td><td>Block the supplied file hashes to the specified file hash block list.</td><td>block_hash <br/>Containment</td></tr>
<tr><td>Search Indicator</td><td>Retrieves the indicators from the specified list, according to the defined filter.</td><td>search_indicator <br/>Investigation</td></tr>
<tr><td>Delete Indicator</td><td>Removes an indicator from Proofpoint Threat Response based on the input parameters.</td><td>delete_indicator <br/>Investigation</td></tr>
<tr><td>Get Incident By ID</td><td>Get incident metadata from Threat Response.</td><td>get_incident <br/>Investigation</td></tr>
<tr><td>Get Incidents List</td><td>Retrieves all incident metadata from Threat Response by specifying filter criteria such as the state of the incident or time of closure.</td><td>get_incidents <br/>Investigation</td></tr>
<tr><td>Add Comment To Incident</td><td>Adds comments to an existing Threat Response incident, by incident ID.</td><td>add_comment_to_incident <br/>Investigation</td></tr>
<tr><td>Update Comment To Incident</td><td>Update the comments to an existing Threat Response incident, by incident ID.</td><td>update_comment_to_incident <br/>Investigation</td></tr>
<tr><td>Add User To Incident</td><td>Assigns a user to an incident as a target or attacker.</td><td>add_user_to_incident <br/>Investigation</td></tr>
<tr><td>Ingest Alert</td><td>Ingest an alert into Threat Response.</td><td>ingest_alert <br/>Investigation</td></tr>
<tr><td>Close Incident</td><td>Close an incident in Proofpoint Threat Response based on the input parameters you have specified.</td><td>close_incident <br/>Investigation</td></tr>
<tr><td>Verify Quarantine</td><td>Verify if an email has been quarantined.</td><td>verify_quarantine <br/>Investigation</td></tr>
</tbody></table>
### operation: Get Indicators List
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>List ID</td><td>Specify the ID of list to fetch the details.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Add Indicators
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>List ID</td><td>Specify the ID of list to add provided indicators.
</td></tr><tr><td>Indicator</td><td>Specify the Indicator values. Value can be IP Address, URLs, Domains or file hashes. e.g. 192.168.1.1,192.168.1.2
</td></tr><tr><td>Comment</td><td>(Optional) Specify the comment to add with this operation.
</td></tr><tr><td>Expiration</td><td>(Optional) Specify the expiration of the indicator.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Block IP Addresses
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>IP Address</td><td>Specify a comma-separated list of IP addresses to add to the block list.
</td></tr><tr><td>Blacklist ID</td><td>Specify the ID of IP block list.
</td></tr><tr><td>Expiration</td><td>(Optional) Specify the date and time the supplied IP addresses should be removed from the block list.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Block Domain
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Domain</td><td>Specify a comma-separated list of domains to add to the block list.
</td></tr><tr><td>Blacklist ID</td><td>Specify the ID of domain block list.
</td></tr><tr><td>Expiration</td><td>(Optional) Specify the date and time the supplied domains should be removed from the block list.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Block URL
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>URL</td><td>Specify a comma-separated list of URLs to add to the block list.
</td></tr><tr><td>Blacklist ID</td><td>Specify the ID of URL block list.
</td></tr><tr><td>Expiration</td><td>(Optional) Specify the date and time the supplied URLs should be removed from the block list.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Block File Hash
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>File Hash</td><td>Specify a comma-separated list of file hashes to add to the file hash block list.
</td></tr><tr><td>Blacklist ID</td><td>Specify the ID of hashes block list.
</td></tr><tr><td>Expiration</td><td>(Optional) Specify the date and time the supplied file hashes should be removed from the block list.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Search Indicator
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Filter</td><td>(Optional) Specify the filter for the indicator search. e.g. For example, "1.1" will return [1.1.1.1, 22.22.1.1, 1.1.22.22]
</td></tr><tr><td>Blacklist ID</td><td>Specify the ID of the list in which to search.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Delete Indicator
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>List ID</td><td>Specify the ID of list to delete provided members.
</td></tr><tr><td>Indicator ID</td><td>Specify the indicator ID to delete from the list.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Get Incident By ID
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify ID of incident to fetch details.
</td></tr><tr><td>Expand Events</td><td>Specify the events, If false, will return an array of event IDs instead of full event objects. This will significantly speed up the response time of the API for incidents with large numbers of alerts.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Get Incidents List
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>State</td><td>(Optional) Specify the state of the incidents to retrieve. you can choose from New, Open, Assigned, Closed and Ignored
</td></tr><tr><td>Create After</td><td>(Optional) Specify the date and time to retrieve incidents that were created after this date.
</td></tr><tr><td>Created Before</td><td>(Optional) Specify the date and time to retrieve incidents that were created before this date.
</td></tr><tr><td>Closed After</td><td>(Optional) Specify the date and time to retrieve incidents that were closed after this date.
</td></tr><tr><td>Closed Before</td><td>(Optional) Specify the date and time to retrieve incidents that were closed before this date.
</td></tr><tr><td>Expand Events</td><td>(Optional) Specify the expand events check, If false, will return an array of event IDs instead of full event objects. This will significantly speed up the response time of the API for incidents with large numbers of alerts.
</td></tr><tr><td>Limit</td><td>(Optional) Specify the maximum number of incidents to return. The default value is 50.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Add Comment To Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the incident ID.
</td></tr><tr><td>Comment</td><td>Specify the comment to add.
</td></tr><tr><td>Description</td><td>(Optional) Specify the description to add this operation.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Update Comment To Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the incident ID.
</td></tr><tr><td>Comment</td><td>(Optional) Specify the comment to update.
</td></tr><tr><td>Description</td><td>(Optional) Specify the description to add this operation.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Add User To Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the incident ID.
</td></tr><tr><td>Targets</td><td>Specify the list of targets to add to the incident.
</td></tr><tr><td>Attackers</td><td>Specify the list of attackers to add to the incident.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Ingest Alert
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>JSON Version</td><td>Specify the Threat Response JSON version.
Possible values are: 2.0, 1.0. Default is 2.0.
</td></tr><tr><td>Post URL ID</td><td>(Optional) Specify the POST URL of the JSON alert source. You can find it by navigating to Sources -> JSON event source -> POST URL.
</td></tr><tr><td>Attacker</td><td>(Optional) Specify an attacker object in JSON format : "{"attacker" : {...}}". The attacker object must contain one of ["ip_address", mac_address", "host_name", "url", "user"] keys. You can also add the "port" key to the object. For more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0".
</td></tr><tr><td>Classification</td><td>(Optional) Specify the alert classification shown as "Alert Type" in the TRAP UI. you can choose from Malware, Policy Violation, Vulnerability, Network, Spam, Phish, Command and Control, Data Match, Authentication, System Behavior, Impostor, Reported Abuse and Unknown
</td></tr><tr><td>CNC Hosts</td><td>(Optional) Specify the Command and Control host information in JSON format : "{"cnc_hosts": [{"host" : "-", "port": "-"}, ...]}".
Note: Every item of the "cnc_hosts" list is in JSON format. For more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0".
</td></tr><tr><td>Detector</td><td>(Optional) Specify the threat detection tool such as Firewall and IPS/IDS systems (in the format: "{"detector" : {...}}"), which generated the original alert. To see all relevant JSON fields and for more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0".
</td></tr><tr><td>Email</td><td>(Optional) Specify the email metadata related to the alert, in JSON format: "{"email": {...}}". To see all relevant JSON fields and for more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0".
</td></tr><tr><td>Forensics Hosts</td><td>(Optional) Specify the forensics host information in JSON format : "{"forensics_hosts": [{"host" : "-", "port": "-"}...]}".
Note: Every item of the "forensics_hosts" list is in JSON format. For more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0".
</td></tr><tr><td>Link Attribute</td><td>(Optional) Specify the attribute to link to the alerts. you can choose from Target IP Address, Target Hostname, Target Machine Name, Target User, Target Mac Address, Attacker IP Address, Attacker Hostname, Attacker Machine Name, Attacker User, Attacker Mac Address, Email Recipient, Email Sender, Email Subject, Message ID, Threat Filename and Threat Filehash
</td></tr><tr><td>Severity</td><td>(Optional) Specify the severity of the alert. you can choose from Info, Minor, Moderate, Major, Critical, Informational, Low, Medium, High and Critical
</td></tr><tr><td>Summary</td><td>(Optional) Specify the alert summary. This argument will populate the Alert Details field.
</td></tr><tr><td>Target</td><td>(Optional) Specify the target host information in JSON format : "{"target": {...}}". To see all relevant JSON fields and for more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0".
</td></tr><tr><td>Threat Info</td><td>(Optional) Specify the threat information in JSON format: "{"threat_info": {...}}". To see all relevant JSON fields and for more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0".
</td></tr><tr><td>Custom Fields</td><td>(Optional) Specify a JSON object for collecting custom name-value pairs as part of the JSON alert sent to Threat Response, in the format: "{"custom_fields": {..}}". Although there is no limit to the number of custom fields, Proofpoint recommends keeping it to 10 or fewer fields. To see all relevant JSON fields and for more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0".
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Close Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID value of the incident to close.
</td></tr><tr><td>Comment</td><td>Specify the details for the closure notes.
</td></tr><tr><td>Description</td><td>Specify the summary for the closure notes.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
### operation: Verify Quarantine
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Message ID</td><td>Specify the ID value of an email.
</td></tr><tr><td>Time</td><td>Specify the email delivery time (ISO8601 format).
</td></tr><tr><td>Recipient</td><td>Specify the email recipient.
</td></tr></tbody></table>
#### Output

 No output schema is available at this time.
## Included playbooks
The `Sample - proofpoint-threat-response - 1.0.0` playbook collection comes bundled with the Proofpoint Threat Response connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the Proofpoint Threat Response connector.

- Add Comment To Incident
- Add To List
- Add User To Incident
- Block Domain
- Block File Hash
- Block IP
- Block URL
- Close Incident
- Delete Indicator
- Get Incident
- Get Incidents
- Get List
- Ingest Alert
- Search Indicator
- Update Comment To Incident
- Verify Quarantine

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
