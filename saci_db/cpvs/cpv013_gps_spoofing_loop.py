from typing import List

from saci.modeling.device import Controller, Serial, GPSReceiver, Motor, PWMChannel, ESC
from saci.modeling import CPV 

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.lack_gps_filtering_vuln import LackGPSFilteringVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState

class GPSSpoofingLoopCPV(CPV):
    
    NAME = "The GPS Spoofing for Keeping the CPS Position Dead Loop"
    
    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                Serial(),
                Controller(),
                Controller(),
                PWMChannel(), 
                ESC(),
                Motor(),
            ],
            # TODO: this one contains multiple entry:
            # we need to first sending numerical input to the controller
            # then we need to spoof the GPS signal to the GPS receiver
            entry_component=GPSReceiver(),
            exit_component=Motor(),
            
            vulnerabilities=[GPSSpoofingVuln(), LackGPSFilteringVuln(), ControllerIntegrityVuln(), LackSerialAuthenticationVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Idle",
                "Operating mode": "Any",
            },
            
            # TODO: We also want to specify the signal data
            # TODO: Modulate the access level and configuration
            attack_requirements = ["GPS Spoof device (e.g., HackRF SDR)"],
            attack_vectors= [BaseAttackVector(name="GPS Spoofing Signal Injection", 
                                               signal=GPSAttackSignal(src=ExternalInput(), dst=GPSReceiver()),
                                               required_access_level="Remote",
                                               configuration={"duration": "permanent"},
                                                )],
            attack_impacts= [BaseAttackImpact(category='Deny of Service',
                                              description='The CPS’s behavior can be altered in unintended ways, such as stopping mid-sequence, moving intermittently, or executing a sequence not commanded by the operator')],
            
            exploit_steps = [
                "Configure the HackRF device and replace the GPS antenna.",
                "Transmit the spoofed GPS signal using specific commands.",
                "Connect the RemoteController to a computer via USB.",
                "Open a terminal emulator or use provided scripts to send commands.",
                "Input specific control commands"],
            
            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV013"],
        )
        
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass