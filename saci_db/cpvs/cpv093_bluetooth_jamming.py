from saci.modeling import CPV
from saci.modeling.communication import ExternalInput


from saci_db.vulns.ble_jamming_vuln import BLEJammingVuln


from saci.modeling.attack.radio_attack_signal import RadioAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device.bluetooth import Bluetooth
from saci.modeling.state import GlobalState


class BluetoothJammingCPV(CPV):
    NAME = "The Bluetooth Jamming Attack"

    def __init__(self):
        super().__init__(
            required_components=[
                Bluetooth(
                    roles=["peripheral"],
                    supported_protocols=["BLE"],
                    bt_version="v4.2",
                    frequency_band="2.4 GHz ISM",
                ),
                Bluetooth(
                    roles=["central"],
                    supported_protocols=["BLE"],
                    bt_version="v4.2",
                    frequency_band="2.4 GHz ISM",
                ),
            ],
            entry_component=Bluetooth(
                    roles=["peripheral"],
                    supported_protocols=["BLE"],
                    bt_version="v4.2",
                    frequency_band="2.4 GHz ISM",
                ),
            exit_component=Bluetooth(
                    roles=["central"],
                    supported_protocols=["BLE"],
                    bt_version="v4.2",
                    frequency_band="2.4 GHz ISM",
                ),
            vulnerabilities=[BLEJammingVuln()],
            initial_conditions={
                "Position": "Within communication range of the target BLE device",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Active",
                "Operating mode": "Manual or Semi-Autonomous",
            },
            attack_requirements=[
                "Knowledge of target beacon's BTAddr",
                "BLE-capable hardware (e.g., RedBear BLE Nano)",
                "Sufficient TX/RX turnaround time (140 microseconds)",
                "Capability to monitor BLE advertising channels (37, 38, 39)",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Bluetooth Jamming Attack",
                    signal=RadioAttackSignal(
                        src=ExternalInput(), 
                        dst=Bluetooth(
                            roles=["central"], 
                            supported_protocols=["BLE"], 
                            bt_version="v4.2", 
                            frequency_band="2.4 GHz ISM"
                        ),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Reactive narrowband jamming",
                        "frequency_range": "2.4 GHz ISM",
                        "hardware": "BLE-capable hardware (e.g., RedBear BLE Nano)",
                        "target": "BLE advertising packets",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Prevents BLE scanners from discovering peripherals by corrupting advertising packets.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Model the BLE advertising and scanning capabilities of the CPS.",
                "The model must include:",
                "    - BTAddr of the target beacon",
                "    - Peripheral beacon broadcasting on advertising channels (37, 38, 39)",
                "    - Central device scanning for peripherals on advertising channels (37, 38, 39)",

                "TA2 Exploit Steps",
                "Simulate the BLE advertising and scanning capabilities of the CPS and introduce the selective reactive jamming",
                "   - BLE beacon broadcasting on advertising channels (37, 38, 39)",
                "   - Jammer hardware (e.g., RedBear BLE Nano)",
                "   - Channel hopping sequence (37, 38, 39)",
                "   - TX/RX turnaround time (140 microseconds)",
                "   - Jammer positioned within ~1m",

                "TA3 Exploit Steps",
                "Activate the jammer and observe the CPS's behavior in response to the jamming.",
                "   - Observe Advertising Success Rate (ASR) dropping to near zero within ~76 cm of the jammer.",
                "   - Vertify that the BLE advertisement frame on channel 37, 38, 39 are jammed.",
            ],
            associated_files=[],
            reference_urls=[
                "https://ieeexplore.ieee.org/document/7785169",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        return state.has_property("CommunicationLoss", True)

