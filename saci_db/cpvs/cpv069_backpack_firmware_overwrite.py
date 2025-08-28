
from saci.modeling import CPV
from saci.modeling.device import (
    Wifi,
    ExpressLRSBackpack,
    Motor,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.expresslrs_fw_overwrite import ExpressLRSFirmwareOverwriteVuln


class BackpackFirmwareOverwriteCPV(CPV):
    NAME = "Backpack Firmware Overwrite Denial-of-Service via Wi-Fi Configuration Interface"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Wifi(), # This is the entry component (Required)
                ExpressLRSBackpack(), # This is a vulnerable required component (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
           
            entry_component=Wifi(),
            # TODO: more precise can be firmware
            exit_component=Motor(),
            
            vulnerabilities=[ExpressLRSFirmwareOverwriteVuln()],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "0",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Not armed",
                "OperatingMode": "N/A",
            },
            
            attack_requirements=[
                "Computer",
                "Local Wi-Fi access to ExpressLRS network",
                "Web browser",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Firmware Overwrite via Web UI",
                    signal=PacketAttackSignal(
                        src=ExternalInput(), dst=ExpressLRSBackpack(), modality="network_packets"
                    ),
                    required_access_level="Remote",
                    configuration={
                        "payload": "zeros.bin.gz",
                        "method": "Web UI upload",
                        "protocol": "HTTP",
                        "port": "80",
                    },
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of control",
                    description="Overwriting firmware renders transmitter unable to communicate with ground control software, preventing remote arming/disarming of drone.",
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
                    "Verify persistence through controller reboot",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/HII-GS0409380007-CPV003/HII-GS0409380007-CPV003-20250303.docx",
                "https://github.com/senpai-on-fire/owlet-taskboard/blob/main/CPVs/IVV_Feedback/PASS/HII-GS0409380007-CPV003-20250303.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass
