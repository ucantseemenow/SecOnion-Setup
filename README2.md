Based on your setup:

Host OS: Windows 11

VMware: Workstation Pro

Security Onion: Running as a VM

Targets: 5 other VMs (Ubuntu/Windows) + host machine

Goal: Monitor network + host activity

FULL STEP-BY-STEP GUIDE: Monitor Host + VMs with Security Onion in VMware Workstation Pro
PART 1: SETUP NETWORKING IN VMWARE
Step 1: Create a Custom Virtual Network (VMnetX)
This will allow all VMs to communicate and be visible to Security Onion.

Open VMware Workstation Pro.

Go to Edit → Virtual Network Editor.

Click "Change Settings" (admin access).

Click "Add Network…", select VMnet2 (or any unused).

Configure it as:

Type: Host-only (or Custom if you need internet access via NAT)

Promiscuous Mode: Allow All

Apply and save.

Step 2: Attach All VMs to VMnet2
For each VM (Security Onion, Ubuntu, etc.):

Go to VM Settings → Network Adapter.

Set to "Custom: VMnet2" (the one you created).

Check “Connected” and “Connect at power on”.

This ensures all VMs can talk and be seen by Security Onion.

PART 2: CONFIGURE SECURITY ONION VM
Step 3: Run Initial Setup
Boot the Security Onion VM.

Open terminal, run:

bash
sudo so-setup
Choose:

Standalone deployment (since it's both sensor and manager)

Assign interface (e.g., eth0 or ens33) for monitoring

Enable Suricata, Zeek, Wazuh

Set local IP, hostname, and passwords as prompted.

After setup, it may take 10–15 minutes to fully initialize services and dashboards.

PART 3: MONITOR NETWORK TRAFFIC FROM VMs
At this point:

Security Onion sees all traffic between VMs (via VMnet2)

Zeek and Suricata will alert on suspicious activity

Try generating test traffic from any VM:

bash
ping 8.8.8.8
curl http://testmyids.com
Then check alerts in Security Onion's Kibana or SOC dashboard.

PART 4: INSTALL WAZUH AGENT ON VMs + HOST
Ubuntu VMs:

On Ubuntu VM, download and install agent:

bash
curl -sO https://packages.wazuh.com/4.7/wazuh-agent_4.7.1-1_amd64.deb
sudo dpkg -i wazuh-agent_4.7.1-1_amd64.deb

Edit config:

bash
sudo nano /var/ossec/etc/ossec.conf

Set the <server> block:

xml
<server>
  <address>SECURITY_ONION_VM_IP</address>
</server>

Start the agent:

bash
sudo systemctl start wazuh-agent
sudo systemctl enable wazuh-agent

Windows Host:

Download Wazuh agent:
https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.1-1.msi

Install it normally.

During setup, enter the Security Onion VM’s IP as the manager.

After install:

Go to C:\Program Files (x86)\ossec-agent\ossec.conf

Set manager IP if not already.

Run ossec-control.exe or use Wazuh Agent Manager to start the agent.

PART 5: VERIFY AGENT CONNECTIONS
Log into Security Onion SOC:

URL: https://[SecurityOnion-IP]

Use the username/password you set

Open Wazuh app

Confirm that your VMs + host are showing as connected agents


You now have:

Network traffic monitoring between all systems (via Suricata + Zeek)

Host-based monitoring of logs/processes (via Wazuh)

A central dashboard (SOC/Kibana) for alerts and visibility
