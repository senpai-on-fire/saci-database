from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (ControllerHigh, CameraHigh,
                                  MultiCopterMotorHigh, MultiCopterMotorAlgo, CyberComponentBase, TelemetryHigh,
                                  Controller)
from saci.modeling.device.compass import CompassSensorHigh, CompassSensor
from saci.modeling.device.motor.steering import SteeringHigh, Steering
from saci.modeling.state import GlobalState
from saci_db.vulns.knowncreds import WifiKnownCredsVuln

from saci_db.vulns.noaps import NoAPSVuln


class CompassInterferenceCPV(CPV):
    NAME = "The magnet-on-the-compass-DoS CPV"

    def __init__(self):
        # TODO: somehow indicate that we must have physical access?
        super().__init__(
            required_components=[
                CompassSensor(),
                Controller(),
                Steering(),
            ],
            entry_component=CompassSensorHigh(),
            vulnerabilities=[],
        )

    def is_possible_path(self, path: List[CyberComponentBase]):
        required_components = [CompassSensorHigh, ControllerHigh, SteeringHigh]
        for required in required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
