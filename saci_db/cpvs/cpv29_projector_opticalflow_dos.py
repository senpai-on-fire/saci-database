from typing import List
from saci.modeling.device import CyberComponentBase, Motor, OpticalFlowSensor, MultiCopterMotor
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling import CPV
from saci_db.vulns.optical_flow_vuln import OpticalFlowSpoofingVuln
from saci_db.vulns.px4_controller_integerity_vuln import PX4ControllerIntegrityVuln
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.image_attack_signal import ImageAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class ProjectorOpticalFlowCPV(CPV):
    
    NAME = "The Projector Optical Flow CPV"
    
    def __init__(self):
        super().__init__(
            required_components=[
                OpticalFlowSensor(),
                PX4Controller(),
                MultiCopterMotor(),
            ],
            entry_component=OpticalFlowSensor(),
            exit_component=Motor(),
            
            vulnerabilities=[OpticalFlowSpoofingVuln(), PX4ControllerIntegrityVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "None",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "None",
                "Operating mode": "Hold",
            },
            
            attack_requirements=["Projector or Laser-based spoofing device"],
            attack_vectors=[
                BaseAttackVector(
                    name="Optical Flow Spoofing Signal",
                    signal=ImageAttackSignal(
                        src=ExternalInput(),
                        dst=OpticalFlowSpoofingVuln().component,
                        modality="image",
                    ),
                    required_access_level="Physical",
                    configuration={"duration": "permanent"},
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description="CPS drifts uncontrollably or exhibits unintended lateral movement targeted by the attackers."
                )
            ],
            
            exploit_steps=[
                "Position the spoofing device in the UAV's optical flow sensor field.",
                "Project high-contrast patterns using a laser or projector.",
                "Move the projected pattern to mislead corner detection algorithms.",
                "Observe the drone drift following the displacement of the projected pattern.",
            ],
            
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/conference/woot16/woot16-paper-davidson.pdf"],
        )
        
    def is_possible_path(self, path: List[CyberComponentBase]):
        for required in self.required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True
    
    def in_goal_state(self, state: GlobalState):
        pass