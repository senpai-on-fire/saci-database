from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (GPSReceiver, Serial, PWMChannel, ESC, MultiCopterMotor, Telemetry)
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_gps_filtering_vuln import LackGPSFilteringVuln

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController

class PathManipulationCPV(CPV):

    NAME = "The Path Manipulation Attack on Type II Drones"

    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                Serial(),
                Telemetry(),
                ArduPilotController(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=GPSReceiver(),
            exit_component=MultiCopterMotor(),

            vulnerabilities=[GPSSpoofingVuln(), LackGPSFilteringVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Following waypoints",
                "Speed": "Normal",
                "Environment": "Dynamic",
                "Failsafe Mode": "Enabled",
                "OperatingMode": "Mission",
            },
            attack_requirements=[
                "GPS spoofing device capable of introducing artificial waypoints.",
                "Target drone operating in autonomous waypoint-following mode."
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Waypoint Injection via GPS Spoofing",
                    signal=GPSAttackSignal(src=ExternalInput(), dst=GPSReceiver(), modality="gps_signals"),
                    required_access_level="Remote",
                    configuration={"spoofed_waypoints": "Custom path"},
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Mission Disruption",
                    description=(
                        "The attacker injects new waypoints via GPS spoofing, redirecting the drone to follow "
                        "a maliciously defined path instead of its pre-programmed trajectory."
                    ),
                ),
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Model the impact of spoofing into the GPS receiver on the CPS dynamics to verify the attack.",
                        "The model must include:",
                        "    - Controller attitude logic algorithm.",
                        "    - GPS receiver sensor.",
                        "    - Any required physical parameters to simulate CPS dynamics.",
                        "    - Electronic speed controller logic and output.",
                        "    - CPS actuators (e.g., motors) controlled by the ESC.",

                "TA2 Exploit Steps",
                    "Simulate the impact of spoofing into the CPS receiver to verify the validity of the attack.",
                    "Start the simulation allow the CPS to start its intended operation.",
                    "At arbitrary time x, start the GPS spoofing attack into and verify the attack impact.",
                    "Report your findings to TA3.",
                
                "TA3 Exploit Steps",
                    "Analyze the drone’s waypoint-following algorithm to identify vulnerabilities.",
                    "Deploy GPS spoofing signals that simulate new waypoints along a desired trajectory.",
                    "Observe the drone deviating from its pre-programmed path to follow the attacker-defined trajectory.",
                    "Ensure the spoofed waypoints align with the drone's safety constraints to avoid crashes.",
                    "Continue spoofing to guide the drone to the attacker’s desired location."
            ],
            associated_files=[],
            reference_urls=["https://dl.acm.org/doi/10.1145/3309735"],
        )

    def in_goal_state(self, state):
        # Define conditions when the vehicle is in the attack's goal state
        # For example, unstable attitude during critical maneuvers
        pass
