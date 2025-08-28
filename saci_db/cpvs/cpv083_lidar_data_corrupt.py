from saci.modeling import CPV
from saci.modeling.device import Controller, LiDAR, Motor
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import (
    LackSerialAuthenticationVuln,
)  # Needs to be corrected after CPV Submission is updated


class LiDARDataDesynchronization(CPV):
    NAME = "LiDAR Parameter Desynchronization CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                LiDAR(),  # This is the entry component (Required)
                # Serial(), # Removed considering that the LiDAR is inherently connected to the Controller via Serial (Not Required)
                Controller(),  # This is the controller hosting the firmware (Required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANBus(), # Removed for generalization since it's not required and too specific (Not required)
                # CANShield(), # Removed for generalization since it's not required and too specific (Not required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(),  # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            entry_component=LiDAR(),
            exit_component=Motor(),
            vulnerabilities=[
                LackSerialAuthenticationVuln()  # needs updating
            ],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[],
            attack_vectors=[],
            attack_impacts=[],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Extract Arduino Giga R1 firmware firmware using EXPLODE.",
                "Analyze firmware to locate TFmini UART config routine.",
                "Document sensor parameters from Benewake TFmini Plus datasheet",
                "Identify baud‑rate command strings (e.g., 0x42 0x57 0x02 0x00).",
                "TA2 Exploit Steps",
                "Matlab/Simulink model sweeping baud 9 600–115 200 at 1 kHz sample",
                "Confirm buffer overflow below 10 kbaud.",
                "QEMU + Gazebo: inject malformed frames",
                "Verify controller sets distance=500 & triggers stop flag.",
                "TA3 Exploit Steps",
                "**TODO:** Identify method to deliver configuration commands *in situ* (e.g., UART debug header, Wi‑Fi OTA, I2C bridge)",
                "Disconnect LiDAR, connect USB‑TTL, compile & run provided C tool:   gcc lidar_read.c -o lidar_read.",
                "Set baud 9 600, sample 1 kHz via tool; observe frames reduce to 0x59 0x59 only.",
                "Re‑attach to rover, adjust controller baud if possible, and monitor for immediate stop event.r",
            ],
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV010/HII-NGP1AROV2ARR05-CPV010-20250507.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass
