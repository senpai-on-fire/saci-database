from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (
    GPSReceiver,
    Controller,
    MultiCopterMotor,
    CyberComponentBase,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

class GPSCPV(CPV):
    NAME = "The GPS Spoofing CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                PX4Controller(),
                MultiCopterMotor(),
            ],
            entry_component=GPSReceiver(),
            vulnerabilities=[GPSSpoofingVuln(), ControllerIntegrityVuln()],
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Stationary or Moving",
                "Environment": "Open Field or Urban Area",
                "RemoteController": "Active",
                "CPSController": "Active",
                # TODO: only in stabilization mode?
                "Operating mode": "Any",
            },
            attack_requirements=[
                "GPS signal jammer or spoofer (e.g., HackRF SDR)",
                "Line of sight to the drone",
                "Minimal environmental interference",
            ],
            attack_vectors= [BaseAttackVector(name="GPS Spoofing Signal", 
                                               signal=GPSAttackSignal(src=ExternalInput(), dst=GPSSpoofingVuln().component, modality="gps_signals"),
                                               required_access_level="Physical",
                                               configuration={"duration": "permanent"},
                                                )],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description=(
                        "The attacker manipulates the GPS signal to create "
                        "erroneous localization, causing the drone to deviate from its intended path."
                    ),
                ),
            ],
            exploit_steps=[
                "Deploy GPS spoofer near the target's vicinity.",
                "Send modified GPS signals targeting the drone's receiver.",
                "Observe the manipulated localization output.",
                "Guide the drone off its intended trajectory or into dangerous zones."
            ],
            associated_files=[],
            reference_urls=[
                "https://www.usenix.org/conference/usenixsecurity22/presentation/zhou-ce",
            ],
        )
        # TODO: Enhanced representation of the attacker's goal
        self.goal_state = []

        
    def in_goal_state(self, state: GlobalState) -> bool:
        pass