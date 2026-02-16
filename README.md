# Wazuh SIEM Lab: Brute Force Detection and Investigation
## Objective

The purpose of this laboratory experiment was to provide a simulation of a _brute force attack_ on a _Windows operating system_ and to show how it can be detected with the usage of _Wazuh SIEM (Security Information Event Management)_. The project has demonstrated the entire _Security Operations Center (SOC)_ workflow including the simulation of an attack, the ingestion of logs into the system, the generation of alerts about potential incidents, and the investigation of incidents.

In this evaluation, the method of attack employed is one of the most commonly used by adversaries in order to obtain access without authorization through repeated attempts to log in.

The Technique Associated with MITRE ATT&CK:

**T1110 – Brute Force**

https://attack.mitre.org/techniques/T1110/
## Lab Architecture

The lab environment consisted of three virtual machines:

| Machine        | Role                              | IP Address       | OS            |
|---------------|-----------------------------------|------------------|--------------|
| Wazuh Server  | SIEM                              | 192.168.56.102   | Ubuntu Server |
| Windows Target| Victim Machine (Wazuh Agent)      | 192.168.56.103   | Windows 10    |
| Kali Linux    | Attacker Machine                  | 192.168.56.101   | Kali Linux    |
## Network Diagram
               [ Kali Linux ]
        Attacker - 192.168.56.101
                    |
                    | Attack traffic
                    v
             [ Windows Target ]
         Victim - 192.168.56.103
             (Wazuh Agent)
                    |
                    | Log forwarding
                    v
             [ Wazuh Server ]
          SIEM - 192.168.56.102
           (Detection & Alerts)
## Attack flow:

Kali Linux → Windows Target → Wazuh SIEM detection
## Log Flow

Windows Target → Wazuh Agent → Wazuh Server → Alert generated
## Tools Used

- Wazuh SIEM

- VirtualBox

- Ubuntu Server

- Windows 10

- Kali Linux

- Wazuh Agent

- Windows Event Logs

## Attack Simulation
A brute-force attack was completed using _Hydra_ from the Kali Linux system and the Windows Remote Desktop Protocol (RDP) service was the target.


Utilized command:
> **_Hydra -l Administrator -P Rockyou.txt rdp://192.168.56.103_**


This command will generate multiple variations of passwords against the Administrator account with the _Rockyou.txt_ word list.


This example illustrates a _real-world brute-force attack_, as is typically seen in corporate environments.
## Detection

The Wazuh Agent installed on the Windows machine collected logs and forwarded them to the Wazuh Server.

Wazuh analyzed the logs using its detection rules and generated alerts based on suspicious activity.

**Alert characteristics observed:**

- Multiple failed login attempts in short time period

- Same source IP address

- Same target account

- Security Event Log correlation

- High severity alert level

**Relevant Windows Event ID:**

Event ID **4625** — Failed login attempt
## Detection workflow

1 - Attack executed from Kali Linux

2 - Event generated on Windows machine

3 - Wazuh Agent collected event log

4 - Log forwarded to Wazuh Server

5 - Wazuh analyzed log

6 - Alert generated in SIEM dashboard
## Evidence

Wazuh Alert Showing Failed Login Attempts

Brute_Force_evidence/failed_login_attempt.png
## MITRE ATT&CK

T1110 – Brute Force

## Conclusion

Successfully detected brute force activity using Wazuh SIEM.
