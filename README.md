# Brute Force Detection using Wazuh

## Objective

Detect brute force attack against Windows endpoint.

## Lab Setup

- Wazuh Server: **_192.168.56.102_**

- Kali Linux: **_192.168.56.101_**

- Windows Target: **_192.168.56.103_**

## Attack Simulation

Tool used: **_Hydra_**

Command:
> **_hydra -l Administrator -P rockyou.txt rdp://192.168.56.103_**

## Detection

Wazuh detected Event ID **4625** (failed login attempts)

[See evidence in] (wazuh-bruteforce-detection-lab/tree/main/Brute_Force_evidence.md) folder.

## MITRE ATT&CK

T1110 – Brute Force

## Conclusion

Successfully detected brute force activity using Wazuh SIEM.
