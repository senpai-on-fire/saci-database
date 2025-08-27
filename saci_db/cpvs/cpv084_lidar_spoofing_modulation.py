from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (
    Controller,
    LiDAR,
    PWMChannel,
    ESC,
    Motor,
    Serial,
    CANBus,
    CANTransceiver,
    CANShield,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack_vector import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln


class LiDARSpoofingModulation(CPV):
    NAME = "LiDAR Spoofing with Modulation from identical LiDAR model"

    def __init__(self):
        super().__init__(
            required_components=[
                LiDAR(), # This is the entry component (Required)
                # Serial(), # Removed considering that the LiDAR is inherently connected to the Controller via Serial (Not Required)
                Controller(), # This is the controller hosting the firmware (Required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANBus(), # Removed for generalization since it's not required and too specific (Not required)
                # CANShield(), # Removed for generalization since it's not required and too specific (Not required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=LiDAR(),
            exit_component=Motor(),
            
            vulnerabilities=[LiDARSpoofingVuln()],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=[
                "Line-of-sight access to LiDAR receiver",
                "IR laser source",
                "Identical Lidar model to the one used in the rover",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Matched-Modulation LiDAR Injection",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(),
                        dst=LiDAR(),
                    ),
                    required_access_level="Remote",
                    configuration={
                        "methods": ["Replay sensor pulses"],
                        "modality": "Laser pulses",
                        "wavelength": "850nm",
                        "target_effect": "False near obastacle injection",
                    },
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="Rover stops motion and ends mission",
                ),
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Extract STM32H743 firmware using EXPLODE",
                    "Analyze firmware to identify LiDAR signal verification logic",
                    "Map LiDAR data flow and threshold checks",
                    "Document sensor parameters from Benewake TFmini Plus datasheet",
                "TA2 Exploit Steps",
                    "Configure QEMU-based firmware simulation environment",
                    "Simulate LiDAR input signals in Gazebo co-simulation",
                    "Inject crafted distance frames via virtual UART",
                    "Validate detection thresholds trigger emergency stop",
                    "Test different pulse patterns and timing configurations",
                    "Document successful attack parameters",
                "TA3 Exploit Steps",
                    "Initial Hardware Testing:",
                    "Using hex wrench, rotate power block counter-clockwise to power on rover",
                    "Wait for system LEDs to light up",
                    "Press button on power block to remove safety",
                    "Connect to 'Arduino Wifi' network using password 'TSWIZZLE1989'",
                    "Navigate to http://10.0.0.1/ in web browser",
                    "Verify web interface shows 'START LEFT TURN' and 'START RIGHT TURN' buttons",
                    "Press either button to initiate rover movement",
                    'Test baseline obstacle detection by placing object (>= LiDAR height) within 27" of sensor',
                    "Verify rover stops automatically",
                    "Power off rover by rotating power block clockwise until LEDs turn off",
                    "Attack Execution:",
                    "Repeat power-on sequence and initiate rover movement",
                    "Align second TFmini LiDAR with the rover LiDAR",
                    "Use non-IR blocking camera to assist with laser alignment if needed",
                    "Verify rover stops after brief delay with no physical obstacles present",
                    "Document response time and effectiveness",
                    "Power off rover using hex wrench (clockwise rotation until LEDs off)",
                    "Record all observations and system behavior",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV012/HII-NGP1AROV2ARR05-CPV012-20250512.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass
