from typing import List

from saci.modeling.device import CyberComponentBase, Controller, Serial, Motor
from saci.modeling import CPV

from ..vulns.lack_authentification import LackAuthenticationVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class SerialArduinoControl(CPV):
    
    NAME = "The Serial Arduino Control CPV"
    
    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),
                Controller(),
                Motor(),
            ],
            entry_component=Controller(),
            exit_component=Motor(),
            
            vulnerabilities=[LackAuthenticationVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Moving or Idle",
                "Operating mode": "Any",
            },
            
            attack_requirements = "Attacker computer and USB-C cable",
            attack_vectors= [BaseAttackVector(name="USB Connection", 
                                               signal=GPSAttackSignal(src='Attacker\s Computer', dst=LackAuthenticationVuln().component, modality="serial"),
                                               required_access_level="physical",
                                               configuration={"duration": "one-time"},
                                                )],
            attack_impacts= [BaseAttackImpact(category='Control Manipulation',
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
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV014"],
        )
        
    def is_possible_path(self, path: List[CyberComponentBase]):
        for required in self.required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True