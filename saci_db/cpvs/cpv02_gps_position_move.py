from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (GPSReceiver, ESC, MultiCopterMotor)
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.px4_controller_integerity_vuln import PX4ControllerIntegrityVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

class GPSCPV(CPV):
    NAME = "The GPS Spoofing CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                PX4Controller(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=GPSReceiver(),
            exit_component=MultiCopterMotor(),
            vulnerabilities=[GPSSpoofingVuln(), PX4ControllerIntegrityVuln()],
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "None",
                "Environment": "Open Field or Urban Area",
                "RemoteController": "Active",
                "CPSController": "Active",
                # TODO: stabilization machanism when moving?
                "Operating mode": "Any",
            },
            attack_requirements=[
                "GPS signal jammer or spoofer (e.g., HackRF SDR)"],
            attack_vectors= [BaseAttackVector(name="GPS Spoofing Signals Injection", 
                                               signal=GPSAttackSignal(src=ExternalInput(), dst=GPSReceiver(), modality="gps_signals"),
                                               required_access_level="Remote",
                                               configuration={"duration": "Permanent"},
                                                )],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description=(
                        "The attacker manipulates the GPS signal to create erroneous localization, causing the drone to deviate from its intended path."
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