from saci.modeling import CPV

from saci.modeling.device import LiDAR, Controller, PWMChannel, ESC, Motor, Serial
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.environmental_attack_signal import EnvironmentalInterference

from saci.modeling.state import GlobalState

from saci_db.vulns import LiDARSpoofingVuln

class LiDARLightAbsorbCPV(CPV):

    NAME = "The Light Absorption Object Removal LiDAR Attack"

    def __init__(self):
        super().__init__(
            required_components=[
                LiDAR(),
                Serial(), 
                Controller(),
                Controller(),
                PWMChannel(),
                ESC(),
                Motor()
            ],

            entry_component = LiDAR(),
            exit_component = Motor(),

            vulnerabilities=[LiDARSpoofingVuln()],

            initial_conditions = {
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "On", 
                "Operating mode": "Mission"
            },

            attack_requirements=["Non-reflective material capable of dissipating LiDAR beam"],

            attack_vectors = [EnvironmentalInterference(dst=LiDAR(), modality="non-reflective material")],

            attack_impacts = [BaseAttackImpact(category="Manipulation of Control",
                                               description="Obstacles with the non-reflective material do not appear in the environment, causing the CPS to travel across unsafe areas.")],

            exploit_steps = [
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine how the LiDAR sensor affects the control logic.",
                    "Identify the reactions of the CPS to different levels of LiDAR sensor readings.",
                    "Create models for the following components: LiDAR sensor, CPS control logic, ESC logic and output, CPS actuators controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics."
                
                "TA2 Exploit Steps",
                    "Implement a simulation of environmental interference such as the non-reflective materials.",
                    "Run the simulation to analyze how the environmental interference affects the operation of the CPS.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device.",

                "TA3 Exploit Steps",
                    "Use imaging tools and other techniques to catalog all LiDAR related hardware components on the CPS.",
                    "Set up an experiment with the environmental interference for targeting a LiDAR sensor.",
                    "Observe the LiDAR point cloud when it interacts with the region of environmental interference.",
                    "Analyze the CPS's physical response to the incorrect LiDAR point cloud from the environmental interference."
            ],

            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/ngc2_taskboard/tree/main/CPVs/HII-NGP1AROV2ARR05-CPV020"]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO
        pass