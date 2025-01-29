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

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotQuadcopter

class FailSafeAvoidanceCPV(CPV):

    NAME = "Fail-Safe Avoidance Attack on Type III Drones"

    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                Serial(),
                ArduPilotQuadcopter(),
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
                "Environment": "Dynamic or stationary",
                "Failsafe Mode": "Enabled",
                "Operating mode": "Any",
            },
            attack_requirements=[
                "GPS spoofing device with fine-grained control over signal deviations.",
                "Knowledge of the drone's GPS fail-safe mechanism."
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Soft GPS Spoofing to Avoid Fail-Safe Triggers",
                    signal=GPSAttackSignal(src=ExternalInput(), dst=GPSReceiver(), modality="gps_signals"),
                    required_access_level="Remote",
                    configuration={"spoofing_intensity": "Minimal", "timing": "Gradual"},
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Fail-Safe Exploitation",
                    description=(
                        "The attacker avoids triggering the drone's GPS fail-safe mode by introducing gradual "
                        "and consistent spoofing signals, maintaining seamless control over the drone's movements."
                    ),
                ),
            ],
            exploit_steps=[
                "Identify the drone model and its GPS fail-safe mechanism behavior.",
                "Deploy soft GPS spoofing equipment to introduce gradual deviations in the GPS signal.",
                "Ensure the spoofed signals remain consistent with the drone’s expected GPS data.",
                "Monitor the drone’s response to verify that fail-safe mechanisms are not triggered.",
                "Redirect the drone to the attacker’s desired location while avoiding safety interruptions."
            ],
            associated_files=[],
            reference_urls=["https://dl.acm.org/doi/10.1145/3309735"],
        )

    def in_goal_state(self, state):
        # Define conditions when the vehicle is in the attack's goal state
        # For example, unstable attitude during critical maneuvers
        pass
