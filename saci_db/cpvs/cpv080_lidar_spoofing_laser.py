from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Controller, LiDAR, PWMChannel, ESC, Motor, Serial
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack_vector import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln

class LiDARSpoofingStopCPV(CPV):

    NAME = "LiDAR Spoofing Causes False Obstacle Detection and Premature Stop"

    def __init__(self):
        super().__init__(
            required_components=[
                LiDAR(),          
                Serial(),  
                Controller(),    
                Controller(),     
                PWMChannel(),     
                ESC(),            
                Motor(),          
            ],
            entry_component=LiDAR(),
            exit_component=Controller(),

            vulnerabilities=[
                LiDARSpoofingVuln()
            ],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission"
            },

            attack_requirements=[
                "Line-of-sight access to LiDAR receiver",
                "IR laser source",
                "Stable laser orientation within LiDAR FOV",
                "Knowledge of LiDAR detection threshold",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="LiDAR Perception Injection Attack",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(),
                        dst=LiDAR(),
                    ),
                    required_access_level="Remote",
                    configuration={
                        "methods": ["Pattern injection", "Pulse relay spoofing"],
                        "modality": "Laser pulses",
                        "wavelength": "850nm",
                        "target_effect": "False obstacle injection"
                    }
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Control Hijacking",
                    description="LiDAR spoofing causes the rover to falsely detect an obstacle and halt, even with no physical obstruction present."
                ),],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "Extract firmware from STM32H743 flight controller using EXPLODE tool",
                    "Analyze firmware to identify LiDAR signal verification logic",
                    "Locate 'LIDAR KILLED OBJECT TOO CLOSE' string reference",
                    "Map LiDAR data flow and threshold checks",
                    "Document sensor parameters from Benewake TFmini Plus datasheet",
                    "Model laser power requirements vs. detection range",
                    "Analyze pulse timing requirements for successful spoofing",
                
                "TA2 Exploit Steps",
                    "Configure QEMU-based firmware simulation environment",
                    "Simulate LiDAR input signals in Gazebo co-simulation",
                    "Test various laser power levels and angles",
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
                    "Test baseline obstacle detection by placing object (>= LiDAR height) within 27\" of sensor",
                    "Verify rover stops automatically",
                    "Power off rover by rotating power block clockwise until LEDs turn off",
                    "Attack Execution:",
                    "Repeat power-on sequence and initiate rover movement",
                    "Activate IR laser and aim at LiDAR receiver (left side of sensor package)",
                    "Use non-IR blocking camera to assist with laser alignment if needed",
                    "Verify rover stops after brief delay with no physical obstacles present",
                    "Document response time and effectiveness",
                    "Power off rover using hex wrench (clockwise rotation until LEDs off)",
                    "Record all observations and system behavior",
            ],

            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV005/HII-NGP1AROV2ARR05-CPV005-20250425.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass