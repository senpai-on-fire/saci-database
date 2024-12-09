from typing import List

from saci.modeling.device import CyberComponentBase, Controller, GPSReceiver, Motor, ESC
from saci.modeling import CPV

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class GPSPositionStaticCPV(CPV):
    
    NAME = "The GPS Static Position CPV"
    
    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                Controller(),
                Controller(),
                ESC(),
                Motor(),
            ],
            entry_component=GPSReceiver(),
            exit_component=Motor(),
            
            vulnerabilities=[GPSSpoofingVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Moving",
                "Operating mode": "Mission",
            },
            
            # TODO: We also want to specify the signal data
            # TODO: Modulate the access level and configuration
            attack_requirements = ["GPS Spoof device (e.g., HackRF SDR)"],
            attack_vectors= [BaseAttackVector(name="GPS Spoofing Signals Injection", 
                                               signal=GPSAttackSignal(src=ExternalInput(), dst=GPSSpoofingVuln().component, modality="gps_signals"),
                                               required_access_level="Remote",
                                               configuration={"duration": "permanent"},
                                                )],
            attack_impacts= [BaseAttackImpact(category='Loss of control',
                                               description='CPS drives in circles without stopping')],
            
            exploit_steps= ["Configure the HackRF device and replace the GPS antenna.",
                            "Transmit the spoofed GPS signal using specific commands."],
            
            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007"],
        )
        
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass