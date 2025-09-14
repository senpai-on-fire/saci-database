from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.battery_exhaustion_vuln import BatteryExhaustionVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact



from saci.modeling.device import (
    Wifi,
    Battery,
)


class BatteryEnhaustionCPV(CPV):
    NAME = "Battery Exhaustion Attack on CPS"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                Battery(),
            ],
            entry_component=Wifi(),
            exit_component=Battery(),
            vulnerabilities=[BatteryExhaustionVuln()],
            initial_conditions={
                "Position": "Within communication range of the target CPS",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Active",
                "Operating mode": "Manual or Semi-Autonomous",
            },
            attack_requirements=[
                "Computer with SSH client",
                "Knowledge of the CPS's SSH credentials (username)",
                "Not affecting the CPS functionality",
                "Animated GIF that consisted of the same image"

            ],
            attack_vectors=[
                 BaseAttackVector(
                    name="Service Request Power Attack",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Repeated service requests",
                        "hardware": "Computer",
                        "target": "CPS's Wi-Fi network",
                    },
                ),
                BaseAttackVector(
                    name="Battery Exhaustion Attack",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Deliver valid but power-costly content",
                        "hardware": "Computer",
                        "target": "CPS's Wi-Fi network",
                    },
                ),
                BaseAttackVector(
                    name="Malignant Power Attack",
                    signal=PacketAttackSignal(
                        src=ExternalInput(),
                        dst=Wifi(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Injected code to maximize energy use",
                        "hardware": "Computer",
                        "target": "CPS's Wi-Fi network",
                    },
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="The CPS's battery will be exhausted as device remains in active mode, leading to DoS",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Model idle, sleep, and active power consumption of the CPS.",
                "Confirm that t he CPS relies on duty-cycling to conserve energy.",

                "TA2 Exploit Steps",
                "Simulate workloads delivery over Wi-Fi that prevent the CPS from sleeping"
                "Three different types:"
                "    - Service request: continous service requests/login",
                "    - Benign power Attack: resource-intensive content (e.g., animated GIF)",
                "    - Malignant power attack: injected code to maximize energy use",

                "TA3 Exploit Steps",
                "Monitor CPS reponse:"
                "    - Vertify sleep transitions do not occur",
                "    - Measure increased power draw (Pactive > Psleep)"
                "    - Validate the reduction of battery of life by a factor of 30 to 280"
            ],
            associated_files=[],
            reference_urls=[
                "https://ieeexplore.ieee.org/document/1276868",
            ],
        )

    def in_goal_state(self, state):
        return state.has_property("CommunicationLoss", True)
        