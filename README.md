# LetsDefend-SOC176-Investigating-RDP-Brute-Force-Detected

As a Soc Analyst, part of my duty is to monitor and manage security tools, analyze ssuspicous activities like SOC176 RDP brute force, and respond to security incidents.

## What is a Brute Force Attack?

A brute-force attack is when an attacker repeatedly tries many possible credentials (passwords, passphrases, or keys) or authentication attempts until one succeeds. It's noisy, automated, and relies on trial-and-error rather than exploiting a software bug. This same steps or the use of automation such as a bot, script, or bonet can be used to send repeated login attempts in RDP brute force (often in hundreds or thoursands). 

## Selecting a Soc Alert

<img width="1876" height="633" alt="image" src="https://github.com/user-attachments/assets/067e200c-0ff2-4eb9-9e02-8151eb08117d" />

I logged in and took ownership of alert 	SOC176 - RDP Brute Force Detected from the SIEM monitoring section. After assigning the alert to myself, I studied the alert and the reaosn for the triggered is that there was login failure from a single source with different non existing accounts. I therefore went further to create a case with EventID: 234

<img width="876" height="725" alt="image" src="https://github.com/user-attachments/assets/9e58f603-8fd6-402b-93b1-5dde7e12ad4b" />

## Playbook

I used the pre´-defined letsdefend playbook to investigate the alert
<img width="1161" height="305" alt="image" src="https://github.com/user-attachments/assets/2b2a9d20-9a97-48da-b2d1-63948e650877" />

## Enrichment and Context

The playbook suggested that the IP need to be verified. This will indicate if its an "internal or external" IP. The source IP address from the alert is 218.92.0.56 and destination IP address 172.16.17.148. The source IP is an IPV4 Class C address in usable host network range. With this, I can depict that the IP addreaa is External and could pose a threat to the network.

<img width="778" height="252" alt="image" src="https://github.com/user-attachments/assets/87225585-260c-4df7-8e77-aa2f7e5fca83" />

# IP Reputation Check

I checked the reputation of the source IP with the tools listed below:
- VirusTotal
- AbuseIPDB
- Letsdefend TI
  
<img width="843" height="542" alt="image" src="https://github.com/user-attachments/assets/1556470d-76e6-45e1-b3e2-b5ff5a5b6162" />

## Virus Total

<img width="812" height="546" alt="image" src="https://github.com/user-attachments/assets/96fd7f9f-07e6-4350-8563-37d323875dcd" />

From VirusTotal, the IP was flagged by 8/95 security vendors as malicious by AlphaSOC, Fortinet, Lionic, BitDefender, and alphaMountain.ai. I proceeded to the community section in VirusTotal where multiple comments reported that the IP address carried out multiple SSH credential attack attempts.

## AbuseIPDB


<img width="911" height="654" alt="image" src="https://github.com/user-attachments/assets/73018f78-6349-46e2-b93a-32c7fef1bc82" />

It revealed that the IP address was reported 455, 810 times from from 973 distinct sources. 218.92.0.56 was first reported on May 8th 2023, and the most recent report was 3 months ago. The Source IP 218.92.0.56 country is China with domain name Domain Name	chinatelecom.cn.

## LetsDefend Threat Intel (TI)

I  filtered and searched by data type IP

<img width="1857" height="634" alt="image" src="https://github.com/user-attachments/assets/bba60094-33e0-4033-91ae-a7f4473f0b37" />

The Threat intel on LetsDefend reported the source IP 218.92.0.56 as a malicious IP. If we take a look at the endpoint security in LetsDefend, I can see that the destination IP 172.16.17.148 belongs to host user called Matthew  with Last Login: Mar, 07, 2024, 04:00 AM and the alert was reported approxmately 8 hours after with Event Time Mar, 07, 2024, 11:44 AM. I can now confidently say that the Ip maliciously flowing from an external IP to internal IP.

# Traffic Analysis

<img width="871" height="386" alt="image" src="https://github.com/user-attachments/assets/605b3ec4-c8b9-4ccd-94df-cb264c12d7be" />

<img width="1855" height="732" alt="image" src="https://github.com/user-attachments/assets/1cf06bd2-1e84-4569-8b21-b4b5c6e01a14" />


I did a basic search with (Source Address contains "218.92.0.56"), 30 events was recorded also before Mar, 07, 2024, 11:44 from the source IP to internal IP with target port 3389 remote desktop protocol (RDP). Therefore, I can say that the RDP server was targeted.

# Determining the Scope of the Attack

<img width="848" height="346" alt="image" src="https://github.com/user-attachments/assets/e53ada23-1cb1-4508-91ce-d165aef33f32" />
<img width="1266" height="716" alt="image" src="https://github.com/user-attachments/assets/760e4127-9cf2-4db8-abbd-b0861187355c" />

I examined various log section of the Log Management on LetsDefend. The attacker focused on a single destination address 172.16.17.148 that belongs to Matthew host machine. The loge extracted from the alerts are as follow:
- Type OS
- Source_Address 218.92.0.56
- Source Port 18845
- Dest_IP 172.16.17.148
- Dest_Port 3389
- Username Admin
- EventID 4625(An account failed to log on)
- Error_Code 0xC000006D(Unknown user name or bad password

# Log Management

<img width="778" height="414" alt="image" src="https://github.com/user-attachments/assets/da37009d-1cd4-4927-8eba-833d3f62c901" />

<img width="1833" height="549" alt="image" src="https://github.com/user-attachments/assets/da9baf91-9b94-4707-9428-40300e2c7b6a" />

I checked for raw logs to know if the is a successful login with (Source Address contains "218.92.0.56" and Raw Log contains "4624").  The was indeed a successful login. The attcker accessed the host using the username ( Matthew )
- Type OS
- Source_Address 218.92.0.56
- Source Port 31245
- Dest_IP 172.16.17.148
- Dest_Port 3389
- Username Matthew
- EventID 4624(An account was successfully logged on.)
- Logon Type 10(RemoteInteractive)

# Endpoint Analysis

I conducted a search on LetsDefend from Endpoint Security as shown below for more investigation. from the Network Action, going through the event time and destination logs, I can see that the source IP contacted the host.
<img width="1490" height="848" alt="image" src="https://github.com/user-attachments/assets/2b8a441e-00e9-4162-be2a-87fa17541f53" />

Not only that, I proceeded to Terminal History in order to know the activities if the attacker on the machine. I observed the CMD.exe process ("C:\Windows\system32\cmd.exe") at Mar 7 2024 11:45:18. The shows the attacker actuallz run commands in Terminal.

<img width="1539" height="892" alt="image" src="https://github.com/user-attachments/assets/eec41c3a-bcb4-4d21-a7ef-d12446a7ff86" />

# Should I Isolate the Device

<img width="828" height="307" alt="image" src="https://github.com/user-attachments/assets/85176433-6636-419d-af40-d8050f295f31" />

Yes, It should be isloated based on mz findings so far. I therefore, contained the device as shown below because the system was exposed to cyber attack and activites actually took place during the attack.
<img width="1766" height="772" alt="image" src="https://github.com/user-attachments/assets/cb4325b3-d8f1-4fef-9bf4-0b51a3328f36" />

# My Artifacts


<img width="957" height="561" alt="image" src="https://github.com/user-attachments/assets/2cb917a9-a20b-4a99-807a-8f942634be91" />

The section is important because it will help the SOC Analyst to understand and respond to the incidents in a more timely manner and effectively. More artifacts gathered are:

- IP addresses 218.92.0.56.

- Usernames targeted: Admin, matthew, and Guest.

- Event IDs & log excerpts: Windows EventID 4625/4624.

- Command: C:\Windows\system32\cmd.exe
- Command: Whoami
- Command: net user letsdefend
- Command: net localgroup administrators
- Commands: netstat -ano

## Analyst Note SOC176 RDP Brute Force Detected

<img width="792" height="473" alt="image" src="https://github.com/user-attachments/assets/4d9ed284-95aa-4478-b87b-1c8cf6c7dd1c" />

On March 7th, 2024, LetsDefend alerted on an RDP brute force attempt against internal host 172.16.17.148. The malicious source IP 218.92.0.56 executed multiple login attempts targeting several local accounts. While most attempts failed, the adversary successfully authenticated using the Matthew account. Post-compromise, terminal/command-line activity was observed on the endpoint, confirming attacker interaction. The host has been quarantined to prevent lateral movement and is undergoing remediation.

# Recommendations

- Enforce MFA for all remote desktop logons.

- Restrict RDP exposure to VPN or jump-host access only.

- Review password policies and ensure complexity requirements.

- Hunt for lateral movement attempts and persistence mechanisms.

- Educate users on strong password hygiene and brute force risks.

# We Done

I therefore closed the alert as true positive

<img width="1867" height="635" alt="image" src="https://github.com/user-attachments/assets/6f45b777-309a-41c3-8b49-07c6b8c012f7" />

