from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (ControllerHigh, ObjectTracking, CameraHigh,
                                  MultiCopterMotorHigh, MultiCopterMotorAlgo, CyberComponentBase)
from saci.modeling.state import GlobalState

from saci_db.vulns.ml_vuln import DeepNeuralNetworkVuln


class ObjectTrackCPV(CPV):
    NAME = "The Object Tracking CPV"

    def __init__(self):
        ml_vuln = DeepNeuralNetworkVuln()
        super().__init__(
            required_components=[
                ml_vuln.component,
                CameraHigh(),
                ControllerHigh(),
                MultiCopterMotorHigh(),
                MultiCopterMotorAlgo(),
            ],
            entry_component=CameraHigh(powered=True),
            vulnerabilities=[ml_vuln]
        )

        # TODO: how to model the shrinking effect of the object tracker
        # we can compare with the initial one or simply check if the width and height are close to 0
        self.goal_state_conditions = [0.0, 0.0]

    def in_goal_state(self, state: GlobalState):
        for component in state.components:
            # the width and height are close to 0
            # return of component.track(): [x, y, w, h]
            if isinstance(component, ObjectTracking) and component.track()[-2:] == self.goal_state_conditions:
                return True
