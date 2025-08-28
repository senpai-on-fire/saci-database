
from saci.modeling import CPV
from saci.modeling.device import (
    GPSReceiver,
    Motor,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.device import Controller

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_gps_filtering_vuln import LackGPSFilteringVuln



class GPSSpoofingMoveCPV(CPV):
    NAME = "The GPS Spoofing for Moving the CPS Position"

    def __init__(self):
        super().__init__(
            
            required_components=[
                GPSReceiver(), # This is the entry component (Required)
                # Serial(), # Removed considering that the GPSReceiver is inherently connected to the Controller via Serial (Not Required)
                Controller(), # This is the main controller where the firmware is hosted (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ], 
            
            entry_component=GPSReceiver(),
            exit_component=Motor(),
            
            vulnerabilities=[
                GPSSpoofingVuln(),
                LackGPSFilteringVuln(),
                ControllerIntegrityVuln(),
            ],
            
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "None",
                "Environment": "Open Field or Urban Area",
                "RemoteController": "Active",
                "CPSController": "Active",
                # TODO: stabilization mechanism when moving?
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=["GPS signal jammer or spoofer (e.g., HackRF SDR)"],
            
            attack_vectors=[
                BaseAttackVector(
                    name="GPS Spoofing Signals Injection",
                    signal=GPSAttackSignal(
                        src=ExternalInput(), dst=GPSReceiver(), modality="gps_signals"
                    ),
                    required_access_level="Remote",
                    configuration={"duration": "Permanent"},
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description=(
                        "The attacker manipulates the GPS signal to create erroneous localization, causing the drone to deviate from its intended path."
                    ),
                ),
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if it implements security mechanisms such as GPS encryption, filtering, or authentication.",
                    "Identify if the firmware has failsafe mechanisms to prevent GPS spoofing.",
                    "Analyze the CPS control logic to assess how spoofing the GPS readings affects the CPS’s operation.",
                    "Create models for the following components: GPS receiver, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics"
                "TA2 Exploit Steps",
                    "Simulate the impact of the GPS spoofing to verify the impact on the CPS.",
                    "Start the simulation by turning-on the CPS and start its intended operation.",
                    "At arbitrary time x, start the GPS spoofing attack and verify if the CPS changes its trajectory.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Use optical imaging tools to catalog all of the components on the CPS.",
                    "Identify which components contained memory that might contain firmware.",
                    "Extract the firmware from the memory component.",
                    "Check if there's a GPS receiver on the CPS. "
                    "Deploy a GPS spoofer (e.g., HackRF) near the target's vicinity.",
                    "Send modified GPS signals targeting the drone's receiver.",
                    "Observe the manipulated localization output.",
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
