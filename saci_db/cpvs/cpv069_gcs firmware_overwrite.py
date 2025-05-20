from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Controller, GCS, Wifi, Telemetry, PWMChannel, ESC, Motor, Mavlink
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.expresslrs_fw_overwrite import ExpressLRSFirmwareOverwriteVuln

class GCSFirmwareOverwrite(CPV):

    NAME = "GCS Firmware Overwrite Denial-of-Service via Wi-Fi Configuration Interface"

    def __init__(self):
        super().__init__(
            required_components=[
                GCS(),            # Sends command
                Mavlink(),        # Protocol used
                Wifi(),           # Communication medium
                Controller(),     # Processes command / runs control logic
                PWMChannel(),     # Generates PWM signals
                ESC(),            # Converts PWM to motor drive
                Motor(),          # Executes actuation 
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
                "TA3 Exploit Steps",
                    "Turn on the controller.",
                    "Turn on the drone.",
                    "On the operator computer, connect to the ExpressLRS Wi-Fi network with the password 'expresslrs'.",
                    "On the operator computer, open the ground control software and connect to the drone.",
                    "Turn off the drone safety by pressing the black button on the drone for two seconds.",
                    "Navigate to the 'Actions' tab on the ground control software and press the 'Arm/Disarm' button. The drone should be armed and the motors should begin to spin.",
                    "Click the 'Arm/Disarm' button to disarm the drone. The motors should stop spinning.",
                    "Connect the attacker system to the ExpressLRS TX Backpack Wi-Fi network with the password 'expresslrs'.",
                    "On the attacker machine, navigate to http://10.0.0.1 in a web browser.",
                    "Click the 'Choose File' button and select zeros.bin.gz.",
                    "Click 'Update' and wait for the firmware to be uploaded and flashed.",
                    "Observe that the TX Backpack is now non-functional.",
                    "Verify the ground control software is disconnected from the drone and cannot use the above procedure for arming the drone.",
                    "Verify that rebooting the controller does not bring the backpack back online."
            ],

            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV003/HII-NGP1AROV2ARR05-CPV003-20250419.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass