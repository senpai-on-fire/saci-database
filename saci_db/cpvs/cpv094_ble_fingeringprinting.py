from saci.modeling import CPV
from saci.modeling.communication import ExternalInput


from saci_db.vulns.ble_fingeringprinting_vuln import BLEFingeringPrintingVuln


from saci.modeling.attack.radio_attack_signal import RadioAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device.bluetooth import Bluetooth
from saci.modeling.state import GlobalState

class BLEFingeringPrintingCPV(CPV):
    NAME = "The BLE Fingering Printing Attack"

    def __init__(self):
        super().__init__(
            required_components=[
                Bluetooth(roles=["peripheral"], supported_protocols=["BLE"]),
                Bluetooth(roles=["central"], supported_protocols=["BLE"]),
            ],
            entry_component=Bluetooth(roles=["peripheral"], supported_protocols=["BLE"]),
            exit_component=Bluetooth(roles=["central"], supported_protocols=["BLE"]),
            vulnerabilities=[BLEFingeringPrintingVuln()],
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
                "Nearby attacker with BLE sniffer/central capability",
                "Ability to detect advertisement packets in real time",
                "Knowledge of static UUIDs extracted from reverse-engineered firmware",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Passive BLE Fingerprinting",
                    signal=RadioAttackSignal(
                        src=ExternalInput(), 
                        dst=Bluetooth(roles=["peripheral"], supported_protocols=["BLE"])),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Sniff advertisement UUIDs",
                        "hardware": "BLE sniffer (e.g., Raspberry-PI and BLE Antenna)",
                        "target": "Static UUIDs in BLE advertisements",
                    },
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Privacy loss",
                    description="Fingerprinting static UUIDs reveals the CPS device's authetification level",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Reverse-engineer the CPS firmware to identify static UUIDs",
                "Model a UUID-to-device database mapping UUIDs to CPS devices",
                "TA2 Exploit Steps",
                "Simulate BLE sniffer (e.g., Raspberry-PI and BLE Antenna)",
                "Capture advertisement packets and extract static UUIDs",
                "Simulate different authentication levels (e.g., Just Works)"
                "TA3 Exploit Steps",
                "Use the UUID-to-device database to identify the CPS device",
                "Connect to the CPS device and verify the authentication level",
            ],
        )
        associated_files=[],
        reference_urls=[
            "https://dl.acm.org/doi/10.1145/3319535.3354240",
        ],


    def in_goal_state(self, state):
       return state.has_property("CPSDeviceFingerprinted", True)





        