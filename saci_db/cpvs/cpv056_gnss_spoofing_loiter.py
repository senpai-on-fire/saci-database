from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (
    GNSSReceiver,
    Serial,
    PWMChannel,
    ESC,
    MultiCopterMotor,
    Telemetry,
    Motor,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gnss_attack_signal import GNSSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.gnss_spoofing_vuln import GNSSSpoofingVuln
from saci_db.vulns.lack_gnss_filtering_vuln import LackGNSSFilteringVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.propriety_quadcopter_device import ProprietyController

from saci.modeling.device import Controller

class GNSSLoiterModeSpoofingCPV(CPV):
    NAME = "The GNSS Spoofing in Loiter Mode for Gradual Displacement"

    def __init__(self):
        super().__init__(
            
            required_components=[
                GNSSReceiver(), # This is the entry component (Required)
                # Serial(), # Removed considering that the GNSSReceiver is inherently connected to the Controller via Serial (Not Required)
                Controller(), # This is the main controller where the firmware is hosted (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=GNSSReceiver(),
            exit_component=Motor(),
            
            vulnerabilities=[
                GNSSSpoofingVuln(),
                LackGNSSFilteringVuln(),
                ControllerIntegrityVuln(),
            ],
            
            goals=[
                "Gradually displace CPS from its loiter position to a target location"
            ],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Hovering",
                "Environment": "Open Field or Urban Area",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=[
                "GNSS spoofer (e.g., SDR device)",
                "Proximity to the CPS’s operational area",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="GNSS Signal Injection for Loiter Manipulation",
                    signal=GNSSAttackSignal(
                        src=ExternalInput(),
                        dst=GNSSReceiver(),
                        modality="gnss_signals",
                    ),
                    required_access_level="Remote",
                    configuration={"incremental_displacement": "Gradual"},
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Manipulation of Control",
                    description=(
                        "The attacker manipulates the GNSS signals to cause the CPS to believe it has drifted, "
                        "triggering self-correction that results in gradual movement to a target location."
                    ),
                ),
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Model the impact of spoofing into the GNSS receiver on the CPS dynamics to verify the attack.",
                    "The model must include:",
                    "    - Control logic algorithm.",
                    "    - GNSS receiver sensor.",
                    "    - Any required physical parameters to simulate CPS dynamics.",
                    "    - Electronic speed controller logic and output.",
                    "    - CPS actuators (e.g., motors) controlled by the ESC.",
                "TA2 Exploit Steps",
                    "Simulate the impact of GNSS spoofing into the CPS receiver to verify the validity of the attack.",
                    "Start the simulation by allowing the CPS to start its intended operation.",
                    "At arbitrary time x, start the GNSS spoofing attack into and verify the attack impact.",
                    "Report your findings to TA3.",
                "TA3 Exploit Steps",
                    "Deploy GNSS spoofer within the operational range of the CPS.",
                    "Inject spoofed GNSS signals with small, incremental position shifts.",
                    "Exploit the CPS's self-correcting behavior in loiter mode to guide it to a target location.",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://ieeexplore.ieee.org/abstract/document/8535083",
            ],
        )

        self.goal_state = [
            "CPS reaches the target location while maintaining loiter behavior"
        ]

    def in_goal_state(self, state: GlobalState) -> bool:
        target_position = state.get("target_position", None)
        current_position = state.get("CPS_position", None)

        if target_position and current_position:
            threshold = 2  # Meters
            return self._is_within_threshold(
                current_position, target_position, threshold
            )
        return False

    @staticmethod
    def _is_within_threshold(current_position, target_position, threshold):
        x1, y1, z1 = current_position
        x2, y2, z2 = target_position
        distance = ((x2 - x1) ** 2 + (y2 - y1) ** 2 + (z2 - z1) ** 2) ** 0.5
        return distance <= threshold
