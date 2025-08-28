from saci.modeling import CPV

from saci.modeling.device import (
    LiDAR,
    Controller,
    Motor,
)
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.environmental_attack_signal import EnvironmentalInterference

from saci.modeling.state import GlobalState

from saci_db.vulns import LiDARSpoofingVuln


class LiDARLightAbsorbCPV(CPV):
    NAME = "The Light Absorption Object Removal LiDAR Attack"

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
                "CPSController": "On",
                "Operating mode": "Mission",
            },
            
            attack_requirements=[
                "Non-reflective material capable of dissipating LiDAR beam"
            ],
            
            attack_vectors=[
                EnvironmentalInterference(
                    dst=LiDAR(), modality="non-reflective material"
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Manipulation of Control",
                    description="Obstacles with the non-reflective material do not appear in the environment, causing the CPS to travel across unsafe areas.",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine how the LiDAR sensor affects the control logic.",
                    "Identify the reactions of the CPS to different levels of LiDAR sensor readings.",
                    "Create models for the following components: LiDAR sensor, CPS control logic, ESC logic and output, CPS actuators controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics."
                "TA2 Exploit Steps",
                    "Implement a simulation of environmental interference such as the non-reflective materials.",
                    "Run the simulation to analyze how the environmental interference affects the operation of the CPS.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device.",
                "TA3 Exploit Steps",
                    "Place a plywood ramp in front of the rover with an incline of approximately 20 degrees.",
                    "Power on the rover using a hex wrench to rotate the power block counter-clockwise.",
                    "Wait for the rover LEDs to indicate readiness, then press the safety button on the power block.",
                    "Connect both operator and attacker computers to the rover's Wi-Fi network ('Arduino Wifi' using password 'TSWIZZLE1989').",
                    "Open the rover web interface on the operator computer at http://10.0.0.1/.",
                    "Start a mission for the rover and observe that it begins to drive.",
                    "The rover should stop moving as it approaches the ramp.",
                    "Line the bottom area of the ramp with a non-reflective material.",
                    "Start a new mission for the rover and observe that it begins to drive.",
                    "Observe that the rover does not stop as it approaches the ramp and continues to drive up the ramp.",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/tree/main/CPVs/HII-NGP1AROV2ARR05-CPV020"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO
        pass
