from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (GPSReceiver, Serial, PWMChannel, ESC, MultiCopterMotor)
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_gps_filtering_vuln import LackGPSFilteringVuln

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController

class DirectionalManipulationCPV(CPV):

    NAME = "The Directional Manipulation Attack on Type I Drones"

    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                Serial(),
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
                "Heading": "Any",
                "Speed": "Normal",
                "Environment": "Open field or urban area",
                "Failsafe Mode": "Enabled",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "GPS signal jammer or spoofer (e.g., HackRF SDR).",
                "Access to drone operating in Position Hold mode."
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="GPS Spoofing for Directional Control",
                    signal=GPSAttackSignal(src=ExternalInput(), dst=GPSReceiver(), modality="gps_signals"),
                    required_access_level="Remote",
                    configuration={"spoofing_intensity": "Adaptive", "direction": "Any"},
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description=(
                        "The attacker manipulates the drone's position by spoofing GPS signals, "
                        "causing it to move in a controlled direction opposite the spoofed GPS offset."
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
                    "Identify the target drone and confirm it is in Position Hold mode.",
                    "Deploy GPS spoofing equipment in the drone’s vicinity.",
                    "Gradually spoof the GPS position to simulate drifting in the desired direction.",
                    "Observe the drone adjusting its trajectory to correct the perceived error.",
                    "Continuously adjust the spoofed GPS position to guide the drone in the desired direction."
            ],
            associated_files=[],
            reference_urls=["https://dl.acm.org/doi/10.1145/3309735"],
        )

    def in_goal_state(self, state):
        # Define conditions when the vehicle is in the attack's goal state
        # For example, unstable attitude during critical maneuvers
        pass
