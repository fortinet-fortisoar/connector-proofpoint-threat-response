""" Copyright start
  MIT License
  Copyright (c) 2024 Fortinet Inc
  Copyright end """


STATE = {
    "New": "new",
    "Open": "open",
    "Assigned": "assigned",
    "Closed": "closed",
    "Ignored": "ignored"
}

CLASSIFICATION = {
    "Malware": "malware",
    "Policy Violation": "policy-violation",
    "Vulnerability": "vulnerability",
    "Network": "network",
    "Spam": "spam",
    "Phish": "phish",
    "Command and Control": "command-and-control",
    "Data Match": "data-match",
    "Authentication": "authentication",
    "System Behavior": "system-behavior",
    "Impostor": "impostor",
    "Reported Abuse": "reported-abuse",
    "Unknown": "unknown"
}

LINK_ATTRIBUTE = {
    "Target IP Address": "target_ip_address",
    "Target Hostname": "target_hostname",
    "Target Machine Name": "target_machine_name",
    "Target User": "target_user",
    "Target Mac Address": "target_mac_address",
    "Attacker IP Address": "attacker_ip_address",
    "Attacker Hostname": "attacker_hostname",
    "Attacker Machine Name": "attacker_machine_name",
    "Attacker User": "attacker_user",
    "Attacker Mac Address": "attacker_mac_address",
    "Email Recipient": "email_recipient",
    "Email Sender": "email_sender",
    "Email Subject": "email_subject",
    "Message ID": "message_id",
    "Threat Filename": "threat_filename",
    "Threat Filehash": "threat_filehash"
}

SEVERITY = {
    "Info": "info",
    "Minor": "minor",
    "Moderate": "moderate",
    "Major": "major",
    "Critical": "critical",
    "Informational": "Informational",
    "Low": "Low",
    "Medium": "Medium",
    "High": "High"
}
