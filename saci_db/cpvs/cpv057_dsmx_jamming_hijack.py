from saci.modeling import CPV
from saci.modeling.device import (
    GCS,
    SikRadio,
    DSMx,
    Telemetry,
    PWMChannel,
    ESC,
    MultiCopterMotor,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.radio_attack_signal import RadioAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.rf_interference_vuln import RFInterferenceVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.dxmx_jamming_vuln import DSMxJammingProtocolVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller


class DSMxJammingHijackCPV(CPV):
    NAME = "The Icarus DSMx Protocol Hijacking Attack"

    def __init__(self):
        super().__init__(
            required_components=[
                GCS(),
                SikRadio(),
                DSMx(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=GCS(),
            exit_component=MultiCopterMotor(),
            vulnerabilities=[
                RFInterferenceVuln(),
                DSMxJammingProtocolVuln(),
                ControllerIntegrityVuln(),
            ],
            goals=[
                "Hijack the CPS mid-flight by assuming control over DSMx communication"
            ],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Nominal",
                "Environment": "Open Field or Urban Area",
                "RemoteController": "Active",
                "CPSController": "Active",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "DSMX signal hijacker (e.g., SDR device or custom hardware)",
                "Ability to observe DSMx communication (e.g., proximity to CPS)",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="DSMx Protocol Hijacking",
                    signal=RadioAttackSignal(
                        src=ExternalInput(),
                        dst=SikRadio(),
                        modality="radio_signals",
                    ),
                    required_access_level="Remote",
                    configuration={
                        "signal_override": "Timing-Based",
                        "protocol_brute_force": "Enabled",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Hijacking",
                    description=(
                        "The attacker brute-forces the DSMx shared secret and uses timing-based attacks to "
                        "supersede the original controller's signal, enabling them to take full control of the CPS."
                    ),
                ),
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Get the extracted CPS firmware from TA3.",
                "Reverse-engineer the CPS firmware to determine if the DSMX protocol is used",
                "Reverse-engineer the CPS firmware to determine if the Radio Transmitter implements security mechanisms",
                "TA2 Exploit Steps",
                "Implement a simulation of an ARDiscovery flooding attack over Wi-Fi in the CPS model.",
                "Run the simulation to analyze how loss of communication translates to control failure in the CPS device.",
                "Check with TA1 to determine the desired impact on control.",
                "TA3 Exploit Steps",
                "Deploy a device capable of intercepting DSMx protocol communication in the CPS's vicinity.",
                "Observe and record DSMx signals to brute-force the shared secret between the CPS and its controller.",
                "Send timing-based spoofed DSMx signals to override the original transmitter’s control.",
                "Assume full control of the CPS, disregarding the legitimate controller’s commands.",
            ],
            associated_files=[],
            reference_urls=[
                "https://www.engadget.com/2016-10-28-icarus-hijack-dmsx-drones.html",
                "https://arstechnica.com/security/2016/10/hack-lets-attackers-hijack-control-of-drones-mid-flight/",
            ],
        )

        self.goal_state = [
            "Attacker successfully overrides legitimate DSMx control and takes full command of the CPS"
        ]

    def in_goal_state(self, state: GlobalState) -> bool:
        """
        Check if the attacker has successfully hijacked the CPS's control.
        """
        attacker_control = state.get("AttackerControl", False)
        original_controller_disconnected = state.get(
            "OriginalControllerDisconnected", False
        )
        return attacker_control and original_controller_disconnected
