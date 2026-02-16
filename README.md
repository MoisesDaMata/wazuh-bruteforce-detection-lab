# Wazuh SOC Lab – Brute Force Detection

### Objective

Simulate a brute force attack against a Windows endpoint and detect it using Wazuh SIEM.

### Lab Architecture

- Wazuh Server (Ubuntu)

- Kali Linux (Attacker)

- Windows 10 (Target with Wazuh Agent)

### Attack Simulation

Used Kali to simulate brute force attempts using:

> **hydra -l administrator -P rockyou.txt rdp://192.168.X.X**

### Detection

Wazuh detected multiple failed login attempts (Event ID 4625).

### Analysis

Multiple failed logins within short timeframe

Same source IP

Rule triggered in Wazuh

Alert level: High

### MITRE ATT&CK Mapping

Technique: T1110 – Brute Force

### Outcome

Successfully detected brute force activity in real time.
