from typing import List

from saci.modeling.device import CyberComponentBase, Controller, Serial, Motor
from saci.modeling import CPV
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_authentification import LackSerialAuthenticationVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

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
            
            vulnerabilities=[LackSerialAuthenticationVuln],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": ["Moving, Idle"],
                "Operating mode": "Any",
            },
            
            attack_requirements = ["Computer", "USB-C cable"],
            attack_vectors= [BaseAttackVector(name="Serial spoofing Signal", 
                                               signal=GPSAttackSignal(src=ExternalInput(), dst=Serial()),
                                               required_access_level="Physical",
                                               configuration={"duration": "one-time"},
                                                )],
            attack_impacts= [BaseAttackImpact(category='Control Manipulation',
                                              description='The CPS’s behavior can be altered in unintended ways, such as stopping mid-sequence, moving intermittently, or executing a sequence not commanded by the operator')],
            
            exploit_steps = [ # Check with Sh the steps
                "Configure the HackRF device and replace the GPS antenna.",
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
    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass