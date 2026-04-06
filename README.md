# SOC-Home-Lab
SOC Home Lab simulating real-world security monitoring using Splunk and Sysmon, including log ingestion, attack simulation, and custom detection development.

## Objectives
- Build a functional SIEM environment using Splunk
- Simulate real-world attack scenarios
- Develop and test detection rules
- Perform basic incident investigation

## Lab Architecture
- SIEM: Splunk
- Endpoint Monitoring: Sysmon
- Machines:
  - Metasploitable (victim machine)
  - Linux/Kali (attack machine)
- Environment: VirtualBox

## Data Collection
- Configured log forwarding to Splunk
- Ingested:
  - Windows Event Logs
  - Sysmon logs (process creation, network connections, etc.)

## Attack Simulations
- Failed login attempts (brute force behavior)
- PowerShell execution
- Network scanning (e.g., port scans)
- etc

## Detection Use Cases
- Multiple failed login attempts (Event ID 4625)
- Suspicious PowerShell execution
- Unusual network connections

## Example Detection Query
```sql
index=windows EventCode=4625
| stats count by user, src_ip
| where count > 5
