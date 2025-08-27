from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (
    Controller,
    Serial,
    Motor,
    CANBus,
    CANTransceiver,
    CANShield,
)
from saci.modeling.device.sensor import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.state import GlobalState

from saci_db.vulns.compass_spoofing_vuln import CompassSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput


class CompassTemporarySpoofingCPV(CPV):
    NAME = "The Temporary Magnetic Interference on Compass"

    def __init__(self):
        super().__init__(
            
            required_components=[
                CompassSensor(), # This is the entry component (Required)
                # Serial(), # Removed considering that the CompassSensor is inherently connected to the Controller via Serial (Not Required)
                Controller(), # This is the controller hosting the firmware (Required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANBus(), # Removed for generalization since it's not required and too specific (Not required)
                # CANShield(), # Removed for generalization since it's not required and too specific (Not required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Steering(),  # This is the exit component (Required)
            ],
            
            entry_component=CompassSensor(),
            exit_component=Motor(),
            
            vulnerabilities=[CompassSpoofingVuln(), ControllerIntegrityVuln],
            
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
            
            attack_requirements=["Magnet with adequate shapes and dimensions"],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Magnetic Signals Interference",
                    signal=MagneticAttackSignal(
                        src=ExternalInput(), dst=CompassSensor()
                    ),
                    required_access_level="Physical",
                    configuration={"duration": "10 sec"},
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of control",
                    description="CPS drives in circles without stopping",
                ),
                BaseAttackImpact(
                    category="Loss of control",
                    description="over/under steer of the desired turning angle",
                ),
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse engineering the extracted firmware using a combination of standard software reverse engineering tools and Binsync.",
                    "Provide context for what the firmware is supposed to do when interacting with sensors (e.g., compass).",
                    "Check if the firmware accepts inputs from the compass sensor.",
                    "Identify the code that is implementing the CPS heading calculation from the compass.",
                    "Check if the code implements any filtering mechanism for compass readings.",
                    "Create models for the following components: Compass, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics"
                "TA2 Exploit Steps",
                    "Simulate the impact of temporary heading mis-calculation on the CPS dynamics",
                    "Start the simulation by turning-on the CPS device.",
                    "At arbitrary time x, start injecting errors into the compass sensor for y seconds",
                    "Change the orientation of the CPS in the simulation and observe the impact on the compass readings"
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Use Optical imaging tools to catalog all of the components on the CPS device.",
                    "Identify if the CPS device has a compass.",
                    "Prepare a powerful magnet with adequate shapes and dimensions.",
                    "Install the magnet on top of the compass.",
                    "Until observing change in the compass readings, keep doing the following: Point the CPS device at a different direction then install the magnet on top of the compass."
                    "Leave the magnet in place for at least 10 seconds.",
                    "Remove the magnet.",
                    "Rotate the CPS 45 degrees in either direction and observe that the compass readings do not significantly change as the CPS rotates."
                    "Rotate the CPS 180 degrees from the original heading. The compass readings should either not significantly change or not change until near 180 degrees.",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
