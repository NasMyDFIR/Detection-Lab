# Detection Lab

## Objective
[Brief Objective - Remove this afterwards]

The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

### Skills Learned
[Bullet Points - Remove this afterwards]

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used
[Bullet Points - Remove this afterwards]

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

# Detection Lab - Part 1

## **Environment Planning & PFsense Firewall Installation**

This section outlines the initial setup of the detection engineering lab, including the network diagram design, virtual machine planning, and the installation of the PFsense firewall. The objective of this phase is to establish a controlled, multi-VM environment for ingesting logs into a SIEM and simulating real-world attack scenarios.

## **Lab Overview**

This detection lab consists of **6 virtual machines**, each serving a distinct role in the simulated enterprise network:

| Component                              | Purpose                                         |
| -------------------------------------- | ----------------------------------------------- |
| **PFsense Firewall**                   | Network segmentation, routing, WAN/LAN handling |
| **Splunk Server**                      | SIEM for log ingestion & analysis               |
| **Active Directory Domain Controller** | Authentication, user management, event logs     |
| **Zeek + Suricata Server**             | Network IDS + packet analytics                  |
| **Windows 10 Workstation**             | User endpoint for simulation & telemetry        |
| **Kali Linux Attacker VM**             | Executes simulated attacks                      |

The environment is designed to mimic a small but realistic corporate network for detection engineering and defensive testing.

## **1. Designing the Network Diagram**

Using **draw.io**, the following components were outlined:

* ☁ **Internet**
* 🔥 **PFsense Firewall**
* 🖥️ **Splunk Server**
* 🧩 **Active Directory Domain Controller**
* 📡 **Zeek + Suricata IDS Server**
* 💻 **Windows 10 Workstation**
* 🦠 **Kali Linux Attacker**
* 🔀 **Layer-2 Switch** connecting internal hosts

Each host is logically placed behind the firewall, with the attacker VM functioning as an internal “red team” device for demonstration, even though a real attacker would sit outside the LAN.

## **2. Initial Network Configuration Plan**

**WAN Network (PFsense external interface)**
To be assigned dynamically depending on network adapter bridging.

**LAN Network (PFsense internal interface)**
Default planned range:

```
192.168.1.0/24  
PFsense LAN IP: 192.168.1.1
```

The PFsense WAN IP will be based on VMware bridging settings.

## **3. Installing PFsense on VMware Workstation Pro**

### **Step 1 - Download PFsense**

* Navigate to **[https://pfsense.org]**
* Select **Download → ISO Image → 2.7.2** (Community Edition)
* Create an account to receive the download link

## **4. Creating the PFsense VM**

### VM Specs:

```
CPU: 1 core
RAM: 2 GB recommended (install fails with 256 MB)
Disk: 30 GB
OS Type: Other / FreeBSD 64-bit
```

### Enable Two Network Adapters:

| Adapter               | Mode                    | Purpose |
| --------------------- | ----------------------- | ------- |
| **Network Adapter 1** | Bridged or Custom VMnet | WAN     |
| **Network Adapter 2** | NAT                     | LAN     |

> **Important:**
> If your host uses **Wi-Fi**, configure **VMNet0** to bridge to your wireless adapter manually via *Virtual Network Editor*.

## **5. Fixing Common Network Adapter Issues**

If WAN cannot reach the internet during installation:

1. Open **Virtual Network Editor**
2. Set **VMNet0 → Bridged → Wi-Fi Adapter**
3. Remove unused VMNet networks
4. Reconfigure PFsense NICs accordingly

## **6. Running the PFsense Installer**

1. Boot from the ISO
2. Choose:

   * *Accept*
   * *Install*
   * *Auto (ZFS)*
   * *Stripe*
3. Select latest **Community Edition**
4. Assign interfaces:

Identify adapters by MAC address:

```
em0 → WAN interface (matches bridged NIC MAC)
em1 → LAN interface (matches NAT NIC MAC)
```

5. PFsense completes installation
6. Reboot

## **7. Confirm Post-Install Interface Assignments**

Example output:

```
WAN  → 10.0.0.243   (dynamic address)
LAN  → 192.168.1.1  (default gateway)
```

Update your diagram with:

* **WAN:** 10.0.0.243/24
* **LAN:** 192.168.1.0/24

## **8. Lab Network Diagram (Conceptual)**

<div>
    <img src="https://i.imgur.com/7YwJhOR.png" />
</div>

*Ref 1: Network Diagram*

# Detection Lab - Part 2

## **Active Directory Domain Controller (ADDC) Deployment**

In this phase of the Detection Engineering Lab, we deploy a **Windows Server 2022 Domain Controller**, configure Active Directory, create organizational units, add users, and join a Windows 10 workstation to the domain. This forms the backbone for enterprise identity telemetry used throughout the detection lab.

## **Objectives**

* Install **Windows Server 2022 Standard**
* Promote the server to a **Domain Controller (ADDS)**
* Create base **Organizational Units (OUs)** and users
* Configure a **static IP** for the server
* Join a Windows 10 workstation to the domain
* Prepare environment for Group Policy & event logging

## **1. Download & Prepare Windows Server 2022**

1. Search: **“Windows Server ISO”**
2. Download **Windows Server 2022 Standard (Evaluation)**
   * Requires registration
3. Save ISO for use in VMware Workstation

## **2. Create the Server VM in VMware Workstation**

### VM Configuration

| Setting    | Value                         |
| ---------- | ----------------------------- |
| Name       | `ADDC01`                      |
| OS         | Windows Server 2022 Standard  |
| Disk       | 60 GB                         |
| Memory     | **4 GB** (2 GB caused issues) |
| Processors | 1                             |
| Network    | NAT (LAN network)             |

> ❗ If auto-install fails (“Cannot find license terms”), disable VMware’s Autoinstall/Floppy settings and proceed with manual installation.

## **3. Install Windows Server 2022**

1. Boot the VM
2. Choose:
   * **Standard Evaluation (Desktop Experience)**
3. Accept license → Custom Install → Next
4. After installation, set Administrator password
5. Log in and dismiss *Server Manager* (will appear automatically)

## **4. Rename the Server**

1. Open **Settings → System → About**
2. Click **Rename this PC**
3. Set to:

```
ADDC01
```

4. Restart the VM

## **5. Assign a Static IP Address**

Network → Adapter Settings → IPv4 Properties:

| Field         | Value                          |
| ------------- | ------------------------------ |
| IP            | `192.168.1.10`                 |
| Subnet        | `255.255.255.0`                |
| Gateway       | `192.168.1.1` (PFsense LAN IP) |
| Preferred DNS | `192.168.1.1`                  |
| Alternate DNS | `8.8.8.8`                      |

Validate:

```cmd
ping 192.168.1.1
```

## **6. Install Active Directory Domain Services**

1. Open **Server Manager**
2. Select **Manage → Add Roles and Features**
3. Choose:
   * **Role-based installation**
   * Server: `ADDC01`
4. Install:
   ```
   Active Directory Domain Services (ADDS)
   ```
5. After installation → click the yellow flag →
   **“Promote this server to a domain controller”**

## **7. Create New Forest / Domain**

Choose:

```
Add a new forest
Domain: MYDFIR.local
Forest Functional Level: Windows Server 2016
Domain Functional Level: Windows Server 2016
```

Set Directory Services Restore Mode (DSRM) password → Next → Install.

The server will restart.

## **8. Verify Domain Controller Installation**

Log in again:

```
MYDFIR\Administrator
```

Verify:

* **System Properties → Domain: MYDFIR.local**

## **9. Create OUs and Users**

Open:

```
Active Directory Users and Computers
```

Create Organizational Units:

```
Finance
IT
Sales
```

Create users:

### Finance → Sally Smith

```
Username: sally
Password: (set & uncheck “User must change password at next logon”)
```

### IT → Steven MyDFIR

```
Username: steven
Password: (set)
```

### Sales → Bob Smith

```
Username: bob
Password: (set)
```

## **10. Join Windows 10 Workstation to the Domain**

> Note: Windows 10 **Pro** edition is required.

### Fix networking first

Windows workstation default IP was not on the LAN subnet.

Set static IP:

| Field         | Value                              |
| ------------- | ---------------------------------- |
| IP            | `192.168.1.100`                    |
| Gateway       | `192.168.1.1`                      |
| Preferred DNS | `192.168.1.10` (Domain Controller) |
| Alternate DNS | `192.168.1.1`                      |

Validate:

```cmd
ping 192.168.1.1
ping 192.168.1.10
```

### Join the domain

1. Right-click **This PC → Properties**
2. **Rename this PC (Advanced)**
3. Domain:

   ```
   MYDFIR.local
   ```
4. Enter credentials:

```
User: MYDFIR\Administrator
```

5. Restart Windows 10

## **11. Test Domain Login**

On Windows 10 → login screen:

Select **Other user**

Log in as:

```
Username: mydfir\steven
Password: <password>
```

If login succeeds → Active Directory is functioning properly.
