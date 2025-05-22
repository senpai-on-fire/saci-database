from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.magnetometer_spoofing_vuln import MagnetometerSpoofingVuln
from saci_db.vulns.lack_emi_sensor_shielding_vuln import LackEMISensorShieldingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_emi_powercable_shielding_vuln import (
    LackEMIPowerCableShieldingVuln,
)

from saci.modeling.device import (
    Controller,
    Serial,
    Magnetometer,
    Steering,
    PowerCable,
    CANBus,
    CANTransceiver,
    CANShield,
)
from saci.modeling.state import GlobalState


class EMIPowerCableMagnetometerCPV(CPV):
    NAME = "The EMI Spoofing Attack on Magnetometer Sensors"

    def __init__(self):
        super().__init__(
            required_components=[
                PowerCable(),
                Magnetometer(),
                Serial(),
                Controller(),
                CANTransceiver(),
                CANBus(),
                CANShield(),
                Controller(),
                Steering(),
            ],
            entry_component=Magnetometer(),
            exit_component=Steering(),
            vulnerabilities=[
                MagnetometerSpoofingVuln(),
                LackEMISensorShieldingVuln(),
                LackEMIPowerCableShieldingVuln(),
                ControllerIntegrityVuln(),
            ],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Active",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "Relative proximity between power cable and magnetometer",
                "Physical access",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Electromagnetic Signals Interference",
                    signal=MagneticAttackSignal(
                        src=PowerCable(),
                        dst=Magnetometer(),
                    ),
                    required_access_level="Physical",
                    configuration={
                        "attack_method": "Move power cable near magnetometer to enhance potential EMI",
                        "duration": "temporary",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Control",
                    description="Rover drives past nominal turning point leading to undershoot or overshoot",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Model the impact of fault injection into the serial communication channel on the drone flight to verify the validity of the attack.",
                "The model must include:",
                "    - Controller attitude logic algorithm.",
                "    - Magnetoemter sensor outputs at the bit level.",
                "    - Any required physical parameters to simulate CPS operation.",
                "    - Electronic speed controller logic and output.",
                "    - CPS actuators (e.g., motors) controlled by the ESC.",
                "TA2 Exploit Steps",
                "Simulate the impact of fault injection into the magnetometer sensor readings.",
                "At arbitrary time x, start the fault injection into the magnetometer sensor and verify the attack impact.",
                "This simulation does not need to include any ElectroMagnetic Interference (EMI); instead, force random bits to be transmitted throughout the simulation.",
                "Report your findings to TA3.",
                "TA3 Exploit Steps",
                "1.Locate the magnetometer in the CPS.",
                "2.Locate the power cables in close proximity to the magnetometer.",
                "3.Position one of the power cables as close as possible to the magnetometer, securing it with a tape.",
                "4.Do a test run on the CPS and monitor the CPS's behavior for signs of orientation miscalculation or navigation errors.",
                "5.If no effect is observed, repeat steps 3 & 4 with other power cables in close proximity to magnetometer.",
            ],
            associated_files=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV014/CPV_video_clips_v2.compressed.mp4"
            ],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV014/HII-NGP1AROV2ARR05-CPV014-20250513.docx",
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV014/CPV_candidate_8.docx",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: ?
        pass
        # Define the goal state, such as orientation estimation error or navigation disruption
        # return state.has_property("OrientationEstimationError", True) or state.has_property("NavigationDisruption", True)
