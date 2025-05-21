from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Controller, LiDAR, PWMChannel, ESC, Motor, Telemetry, Serial
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack_vector import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln

class LiDARBYPASSMirrorCPV(CPV):

    NAME = "LiDAR Mirror Reflection Prevents Obstacle Detection, Allows Collision"

    def __init__(self):
        super().__init__(
            required_components=[
                LiDAR(),   
                Serial(),       
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
                "Environment": "Indoor or controlled outdoor",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission"
            },

            attack_requirements=[
                "Physical access within LiDAR range (< 27 inches)",
                "Mirror material (minimum 4x4 inches)",
                "Ability to maintain stable 45° angle",
                "Clear line-of-sight to LiDAR sensor",
                "Understanding of LiDAR detection threshold"
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Mirror-Based LiDAR Signal Redirection",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(),
                        dst=LiDAR()
                    ),
                    required_access_level="Physical",
                    configuration={
                        "material": "Reflective mirror surface",
                        "placement": "27 inches or closer to LiDAR",
                        "angle": "45° relative to sensor plane",
                        "goal": "Redirect LiDAR signal to create false distance reading",
                        "effect": "Prevents obstacle detection"
                    }
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Control Hijacking",
                    description="Mirror-based LiDAR signal redirection causes the rover to fail to detect obstacles, potentially leading to collisions."
                )
            ],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "Extract firmware from STM32H743 controller using EXPLODE tool",
                    "Analyze firmware to identify LiDAR signal processing logic",
                    "Locate 'LIDAR KILLED OBJECT TOO CLOSE' string reference",
                    "Map LiDAR data flow and threshold checks",
                    "Document sensor parameters and timing requirements",
                    "Model mirror reflection angles and detection thresholds",
                
                "TA2 Exploit Steps",
                    "Configure QEMU-based firmware simulation environment",
                    "Simulate LiDAR signal reflection in Gazebo",
                    "Test various mirror angles and distances",
                    "Validate detection threshold bypass conditions",
                    "Document successful attack parameters",
                
                "TA3 Initial Hardware Testing:",
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
                    "Repeat power-on sequence and initiate rover movement",
                    "Position mirror at 45° angle in front of LiDAR sensor",
                    "Ensure mirror surface is clean and properly aligned",
                    "Place actual obstacle behind or beside mirror setup",
                    "Observe rover continues movement despite obstacle presence",
                    "Verify rover fails to detect obstacle at expected distance",
                    "Document attack success and system behavior",
                    "Use emergency stop via web interface if needed",
                    "Power off rover using hex wrench (clockwise rotation until LEDs off)"
            ],

            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV003/HII-NGP1AROV2ARR05-CPV003-20250419.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Implement goal state logic if required
        pass