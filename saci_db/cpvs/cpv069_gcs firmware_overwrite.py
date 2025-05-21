from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Controller, GCS, Wifi, Telemetry, PWMChannel, ESC, Motor, Mavlink
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.expresslrs_fw_overwrite import ExpressLRSFirmwareOverwriteVuln
from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController


class GCSFirmwareOverwriteCPV(CPV):

    NAME = "GCS Firmware Overwrite Denial-of-Service via Wi-Fi Configuration Interface"

    def __init__(self):
        super().__init__(
            required_components=[
                GCS(),            
                Mavlink(),        
                Wifi(),           
                ArduPilotController(),     
                PWMChannel(),     
                ESC(),            
                Motor(),  
            ],
            entry_component=Wifi(),
            # TODO: more precise can be firmware
            exit_component=Controller(),

            vulnerabilities=[
                ExpressLRSFirmwareOverwriteVuln()
            ],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "0",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Not armed",
                "OperatingMode": "N/A"
            },

            attack_requirements=[
                "Computer",
                "Local Wi-Fi access to ExpressLRS network",
                "Web browser"
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Firmware Overwrite via Web UI",
                    signal=PacketAttackSignal(
                        src=ExternalInput(), 
                        dst=Telemetry(),
                        modality="network_packets"
                    ),
                    required_access_level="Remote",
                    configuration={
                        "payload": "zeros.bin.gz", 
                        "method": "Web UI upload",
                        "protocol": "HTTP",
                        "port": "80"
                    }
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of control",
                    description="Overwriting firmware renders transmitter unable to communicate with ground control software, preventing remote arming/disarming of drone."
                )
            ],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "No simulation steps required for this exploit",
                
                "TA2 Exploit Steps",
                    "No simulation steps required for this exploit",
                
                "TA3 Exploit Steps",
                    "Initial System Analysis:",
                    "Power on transmitter and observe exposed Wi-Fi network (SSID: ExpressLRS TX Backpack ###)",
                    "Document Wi-Fi password: 'expresslrs'",
                    "Verify web interface accessibility at http://10.0.0.1",
                    
                    "Baseline Functionality Verification:",
                    "Turn on controller and drone",
                    "Connect operator computer to ExpressLRS Wi-Fi network",
                    "Open ground control software and establish drone connection",
                    "Disable drone safety (press black button for 2 seconds)",
                    "Test arm/disarm functionality via ground control software",
                    "Verify motor response to commands",
                    
                    "Attack Execution:",
                    "Connect attack system to ExpressLRS TX Backpack Wi-Fi",
                    "Access web interface at http://10.0.0.1",
                    "Upload zeros.bin.gz via 'Choose File' button",
                    "Initiate firmware update",
                    "Verify TX Backpack becomes non-functional",
                    "Confirm ground control disconnection",
                    "Verify persistence through controller reboot"
            ],

            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV003/HII-NGP1AROV2ARR05-CPV003-20250419.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass