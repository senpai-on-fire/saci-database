from typing import List, Type
from saci.modeling import CPV
from saci.modeling.device import (ControllerHigh, CameraHigh,
                                  MultiCopterMotorHigh, MultiCopterMotorAlgo, CyberComponentBase, TelemetryHigh,
                                  MotorHigh, Controller, Motor)
from saci.modeling.device.motor.steering import SteeringHigh
from saci.modeling.state import GlobalState
from saci_db.vulns.knowncreds import WifiKnownCredsVuln

from saci_db.vulns.noaps import NoAPSVuln


class WebStopCPV(CPV):
    NAME = "The stop-via-the-web CPV"

    def __init__(self):
        known_creds = WifiKnownCredsVuln()
        super().__init__(
            required_components=[
                known_creds.component,
                Controller(),
                Motor(),
            ],
            entry_component=known_creds.component,
            vulnerabilities=[known_creds]
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "Software state (RemoteController)": "On",
                "Software state (CPSController)": "Moving",
                "Operating mode": "???"
            },
            attack_requirements=[
                "Attacker computer.",
                "Hardcoded credentials"
            ],
            exploit_steps=[
                "Connect to rover Wi-Fi using hardcoded credentials",
                "Attacker issue a long HTTP GET request (at least 26,000 characters) to the webserver address",
                "The CPS was attacked, and the operator found that the CPS could not be stopped."
            ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV003/HII-NGP1AROV1ARR03-CPV003-20240828.docx"]
        )

    def is_possible_path(self, path: List[CyberComponentBase]):
        required_components = [TelemetryHigh, ControllerHigh, MotorHigh]
        for required in required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
