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
    DESCRIPTION = """The rover uses the readings from a digital compass to determine when it has reached the desired 
    heading. This heading is calculated from the current heading when the rover finishes its first 7m driving 
    segment. Under normal operation the rover will turn the wheels left or right and continue to drive until the 
    desired heading is reached, at which time it will straighten the wheels and begin its second 7m driving segment. 
    A CPV can be exposed by affixing a small magnet to the top of the compass. This will cause the compass heading to 
    be “fixed” and not reflect a change when the rover’s heading has changed. There is still some variability but 
    appears to be in the 1%-5% range. The physical effect manifested by this CPV is that rover will drive in a circle 
    while it is attempting to find it’s desired heading and never start the second 7m driving segment."""

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
            initial_conditions=[
                "software state: on, rover idle"   ,
            ],
            final_conditions=[
                "rover drives in circle",
            ],
            steps=[
                "power rover on",
                "install magnet on top of compass",
                "give rover drive command",
            ],
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
