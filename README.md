# SecOnion-Setup
This is an instructional repo for explaining how to setup SecOnion within Host Machine and within the VM's


###  What is Security Onion?

Security Onion is a Linux distribution for intrusion detection, network security monitoring, and log management. It includes tools like Suricata, Zeek, Wazuh, and more.

---

##  **How to Monitor the Host Machine from a Security Onion VM**

There are **two main approaches**, depending on what type of monitoring you want:

---

###  **1. Monitor Host Network Traffic (via Promiscuous Mode)**

If you're using **VMware Workstation/Player** or **VMware ESXi**, you can do the following:

####  Steps:

1. **Configure Security Onion VM’s NIC** to be in **Bridged Mode** or **Custom (promiscuous)** network.
2. **Enable Promiscuous Mode** in the VMware network adapter settings:

   * Go to VM settings → Network Adapter → Advanced → **Promiscuous Mode** → **Allow All**.
3. On the **host machine**, all network traffic should be visible to the VM (depending on bridged/network topology).
4. Start Security Onion with a **network sensor** role (run `so-setup` and choose `Standalone` or `Sensor`).

####  Limitation:

* This only captures **network traffic**, not system logs, processes, or filesystem events of the host.
* **Encrypted traffic (e.g., HTTPS)** will be limited unless decrypted or terminated within the monitored environment.

---

###  **2. Monitor Host Internals (via Wazuh agent)**

If you want to monitor the **host machine's logs, processes, files, etc.** (not just network traffic):

####  Steps:

1. **Install Wazuh agent** on the **host OS** (e.g., Windows or Linux).
2. Configure it to forward logs and events to the **Wazuh manager** running inside your Security Onion VM.
3. In Security Onion, enable Wazuh and configure it to receive logs from agents.

####  Benefit:

* You get **host-based intrusion detection (HIDS)** in addition to network monitoring.

---

##  Example Setup Summary:

| Component          | Host Machine                      | Security Onion VM                        |
| ------------------ | --------------------------------- | ---------------------------------------- |
| Network Role       | Generates traffic / runs services | Monitors network (via bridged interface) |
| Host Monitoring    | Install Wazuh agent               | Collects logs via Wazuh manager          |
| Traffic Visibility | Normal VM traffic / apps          | Promiscuous NIC + Suricata/Zeek          |

---

##  Things to Keep in Mind:

* VMware Player sometimes limits promiscuous mode unless run with admin privileges.
* Packet capture inside a VM may not catch **all traffic** without proper NIC config.
* Ensure Security Onion has sufficient CPU/RAM (minimum 4 CPU, 8 GB RAM recommended).
* Host firewall or antivirus may interfere with monitoring or agent communication.

To **monitor other systems running in VMs** (like Ubuntu) using **Security Onion**, you have two main approaches, depending on what you want to monitor:

---

##  Your Goal: What Do You Want to Monitor?

| Monitoring Type                   | Tool Used      | Method                                                                  |
| --------------------------------- | -------------- | ----------------------------------------------------------------------- |
| **Network Traffic**               | Suricata, Zeek | Set up virtual network mirroring or connect all VMs to a shared network |
| **System Logs, Processes, Files** | Wazuh (HIDS)   | Install the Wazuh agent in the target VM and forward logs               |

---

##  Option 1: **Monitor Network Traffic of Other VMs**

This captures things like:

* Browsing
* SSH connections
* DNS queries
* Suspicious payloads

###  Steps:

1. **Ensure all your VMs (Security Onion + Ubuntu targets) are on the same virtual network**, e.g., `Custom: VMnetX` or `Bridged`.
2. **Enable promiscuous mode** on the Security Onion VM's NIC:

   * VMware → VM Settings → Network Adapter → Advanced → Promiscuous Mode → **Allow All**.
3. Start Security Onion and select **“Standalone” or “Sensor”** role during `so-setup`.
4. Ensure **Suricata** and **Zeek** are enabled to sniff traffic.

> Now, as long as VMs communicate over the same network, **Security Onion will see their traffic**.

---

##  Option 2: **Monitor Host Activities Inside Other VMs (e.g., Ubuntu)**

This is **host-based monitoring**, including:

* Login attempts
* File integrity
* Suspicious processes
* Malware detection

###  Steps:

1. In the **Ubuntu VM**, install the Wazuh agent:

   ```bash
   curl -sO https://packages.wazuh.com/4.7/wazuh-agent-4.7.1.deb
   sudo dpkg -i wazuh-agent-4.7.1.deb
   ```
2. Configure the agent to connect to your **Security Onion’s Wazuh Manager**:
   Edit `/var/ossec/etc/ossec.conf` and set:

   ```xml
   <server>
     <address>SECURITY_ONION_VM_IP</address>
   </server>
   ```
3. Start and enable the agent:

   ```bash
   sudo systemctl enable wazuh-agent
   sudo systemctl start wazuh-agent
   ```
4. In Security Onion, make sure Wazuh manager is enabled during setup or via `so-allow`.

> Once configured, the Ubuntu VM’s system activity will show up in the **Wazuh dashboard** in Security Onion.

---

##  Example Use Case: Full Visibility Setup

You could have:

* **Security Onion in VM1** (Promiscuous mode + Wazuh manager)
* **Ubuntu VM2** (Wazuh agent + same network)
* **Windows VM3** (Wazuh agent + same network)

Security Onion will:

* Use **Zeek/Suricata** to analyze traffic between all VMs
* Use **Wazuh** to monitor internal behavior of each system

---
