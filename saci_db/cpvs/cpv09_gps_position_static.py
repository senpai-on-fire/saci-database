from typing import List

from saci.modeling.device import CyberComponentBase, Controller, GPSReceiver, Motor
from saci.modeling import CPV

from ..vulns.gps_spoofing_vuln import GPSSpoofingVuln
from ..vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class GPSPositionStatic(CPV):
    
    NAME = "The GPS Position Static CPV"
    
    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(),
                Controller(),
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
            attack_requirements = "GPS Spoof device (e.g., HackRF SDR)",
            attack_vectors= [BaseAttackVector(name="GPS Spoofing Signal", 
                                               signal=GPSAttackSignal(src='Software-Defined Radio', dst=GPSSpoofingVuln().component, modality="gps"),
                                               required_access_level="physical",
                                               configuration={"duration": "permanant"},
                                                )],
            attack_impacts= [BaseAttackImpact(category='Loss of control',
                                               description='CPS drives in circles without stopping')],
            
            exploit_steps= ["1. Configure the HackRF device and replace the GPS antenna.",
                            "2. Transmit the spoofed GPS signal using specific commands.",
                            "3. Observe the CPS’s behavior as it fails to stop after 7 meters."],
            
            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007"],
        )
        
    def is_possible_path(self, path: List[CyberComponentBase]):
        for required in self.required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True