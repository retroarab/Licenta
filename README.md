# Bluetooth Attack Toolkit - BLUETOOTH PENETRATION TESTING SUITE

## Author: [El Kharoubi Iosif]
#### [**GitHub repository link**](https://github.com/retroarab/Licenta)

### ** IMPORTANT DISCLAIMER**
This toolkit is a **Proof of Concept (PoC)** designed exclusively for educational purposes and authorized penetration testing. It has been specifically tested and optimized for **Android 9 systems**, particularly targeting PX5-based automotive head units.

**Target Device Information:**
- **BD Address:** 00:0D:18:A1:60:58
- **OUI Company:** Mega-Trend Electronics CO., LTD. (00-0D-18)
- **Device Name:** CAR-KIT
- **LMP Version:** 2.1 (0x4) LMP Subversion: 0x16e0
- **Manufacturer:** Cambridge Silicon Radio (10)
- **Platform:** PX5 Android 9 (rk3368-userdebug 9 PQ2a)
- **Kernel:** 4.4.168
- **MCU:** MTCE CHS V3.38_1

### **Installation and Setup Steps**

1. Clone the GitHub repository:
```bash
git clone https://github.com/retroarab/Licenta
cd Licenta
```

2. Install required system dependencies:
```bash
sudo apt update
sudo apt install -y python3 python3-pip bluetooth bluez bluez-tools
sudo apt install -y libbluetooth-dev python3-dev libdbus-1-dev
sudo apt install -y rfkill hcitool sdptool
```

3. Install Python dependencies:
```bash
pip3 install -r requirements.txt
```

If you encounter issues with PyBluez installation, run:
```bash
sudo apt install libbluetooth-dev
pip3 install pybluez
```

4. Install additional Bluetooth utilities:
```bash
sudo apt install -y bluez-hcidump
sudo pip3 install scapy dbus-python pygobject
```

5. Ensure Bluetooth adapters are available:
```bash
hciconfig -a
```
You should see at least `hci0`. For MitM attacks, two adapters (`hci0` and `hci1`) are recommended.

6. Set up proper permissions:
```bash
sudo usermod -a -G dialout $USER
sudo chmod +x bluetooth_attack_suite.py
```

7. Configure Bluetooth services:
```bash
sudo systemctl enable bluetooth
sudo systemctl start bluetooth
```

### **Usage Instructions**

#### **PIN Cracking Attack**
Brute force PIN codes against Bluetooth devices:
```bash
sudo python3 better.py pin_crack
```

#### **Man-in-the-Middle Attack**
Intercept communications between a phone and car system:
```bash
sudo python3 better.py mitm --mac 00:0D:18:A1:60:58 --iface hci1
```

#### **ADB Connectivity Check**
Test ADB access to Android devices:
```bash
python3 better.py adb_connect --ip 192.168.1.100
```

#### **BrakTooth Vulnerability Testing**
Run BrakTooth exploit framework:
```bash
python3 better.py braktooth_run
```

### **Features and Capabilities**

- **PIN Cracking:** Advanced Bluetooth PIN brute-forcing with intelligent retry mechanisms
- **Man-in-the-Middle:** Real-time interception of HFP, SPP, HSP, and other Bluetooth protocols
- **Audio Interception:** SCO audio capture for hands-free profile communications
- **Multi-Adapter Support:** Simultaneous use of multiple Bluetooth adapters
- **Traffic Analysis:** Comprehensive logging and packet capture functionality
- **Service Discovery:** Automated Bluetooth service enumeration and profiling

### **Supported Bluetooth Profiles**

- **HFP (Hands-Free Profile):** Call control and audio routing
- **HSP (Headset Profile):** Basic audio functionality
- **SPP (Serial Port Profile):** Data communication
- **A2DP (Advanced Audio Distribution Profile):** High-quality audio streaming
- **AVRCP (Audio/Video Remote Control Profile):** Media control
- **PBAP (Phone Book Access Profile):** Contact synchronization

### **System Requirements**

- **Operating System:** Linux (Ubuntu 18.04+ recommended)
- **Python Version:** 3.6 or higher
- **Bluetooth Hardware:** 1x Extra USB Bluetooth adapters with CSR chipset recommended ( tested )
- **Privileges:** Root access required for low-level Bluetooth operations
- **Memory:** Minimum 2GB RAM
- **Storage:** 1GB free space for logs and captures

### **Output and Logging**

All attack sessions generate comprehensive logs stored in:
- **Main Log:** `bt_attack_suite.log`
- **Session Data:** `bt_captures/session_YYYYMMDD_HHMMSS/`
- **Audio Captures:** `bt_captures/session_*/SCO_Audio/`
- **Packet Data:** `bt_captures/session_*/[service_name]/`

### **Legal Notice and Ethical Use**

 **LEGAL DISCLAIMER:** This toolkit is intended solely for:
- Authorized penetration testing
- Security research in controlled environments
- Educational purposes in cybersecurity courses
- Assessment of your own devices

**DO NOT USE** this toolkit on devices you do not own or without explicit written permission. Unauthorized access to Bluetooth devices may violate local, national, and international laws.

### **Troubleshooting**

#### **Common Issues:**

1. **"Permission denied" errors:**
```bash
sudo chmod 666 /dev/rfcomm*
sudo usermod -a -G bluetooth $USER
```

2. **Bluetooth adapter not found:**
```bash
sudo rfkill unblock bluetooth
sudo hciconfig hci0 up
```

3. **PyBluez installation fails:**
```bash
sudo apt install libbluetooth-dev python3-dev
pip3 install --upgrade pybluez
```

4. **D-Bus connection errors:**
```bash
sudo systemctl restart bluetooth
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus"
```

### **Contributing**

Contributions are welcome! Please ensure all submissions:
- Follow ethical hacking guidelines
- Include proper documentation
- Are tested in controlled environments
- Respect responsible disclosure practices

### **Research Citations**

If you use this toolkit in academic research, please cite:
```
[El Kharoubi Iosif]. (2025). BLUETOOTH SECURITY VULNERABILITIES IN IN-VEHICLE INFOTAINMENT SYSTEMS GitHub Repository.
```

---

**Remember:** With great power comes great responsibility. Use this toolkit ethically and legally. 
