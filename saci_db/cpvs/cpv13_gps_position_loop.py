from typing import List

from saci.modeling.device import CyberComponentBase, Controller, GPSReceiver, Motor
from saci.modeling import CPV

from ..vulns.gps_spoofing_vuln import GPSSpoofingVuln
from ..vulns.controller_integerity_vuln import ControllerIntegrityVuln
from ..vulns.lack_authentification import LackAuthenticationVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class GPSPositionLoop(CPV):
    
    NAME = "The GPS Position Dead Loop CPV"
    
    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                Controller(),
                Motor(),
            ],
            # TODO: this one contains multiple entry:
            # we need to first sending numerical input to the controller
            # then we need to spoof the GPS signal to the GPS receiver
            entry_component=GPSReceiver(),
            exit_component=Motor(),
            
            vulnerabilities=[GPSSpoofingVuln(), 
                             ControllerIntegrityVuln(), 
                             LackAuthenticationVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Moving",
                "Operating mode": "Any",
            },
            
            # TODO: We also want to specify the signal data
            # TODO: Modulate the access level and configuration
            attack_requirements = "GPS Spoof device (e.g., HackRF SDR)",
            attack_vectors= [BaseAttackVector(name="GPS Spoofing Signal", 
                                               signal=GPSAttackSignal(src='Software-Defined Radio', dst=GPSSpoofingVuln().component, modality="gps"),
                                               required_access_level="physical",
                                               configuration={"duration": "permanant"},
                                                )],
            attack_impacts= [BaseAttackImpact(category='Deny of Service',
                                              description='The CPS’s behavior can be altered in unintended ways, such as stopping mid-sequence, moving intermittently, or executing a sequence not commanded by the operator')],
            
            exploit_steps = [
                "1. Power on the CPS.",
                "2. Configure the HackRF device and replace the GPS antenna.",
                "3. Transmit the spoofed GPS signal using specific commands.",
                "4. Connect the Arduino Uno R4 to a computer via USB.",
                "5. Open a terminal emulator or use provided scripts to send commands.",
                "6. Input specific commands:",
                "    - 77: Initiates a pre-programmed driving sequence.",
                "    - 66: Interrupts the sequence, stopping the rover.",
                "    - 55: Causes intermittent movements with brief motor engagements.",
                "7. Observe the corresponding effects on the CPS."
            ],
            
            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV013"],
        )
        
    def is_possible_path(self, path: List[CyberComponentBase]):
        for required in self.required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True