from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Telemetry, ControllerHigh, MultiCopterMotor, MultiCopterMotorAlgo
from saci.modeling.state import GlobalState
from saci.modeling.device import CyberComponentBase

from ..devices.px4_quadcopter_device import GCSTelemetry
from ..vulns.mavlink_mitm_vuln import MavlinkVuln01
from ..vulns.sik_vuln import SiKAuthVuln01


class MavlinkCPV(CPV):

    NAME = "The Mavlink CPV"

    sik_auth_vuln = SiKAuthVuln01()
    mavlink_vuln = MavlinkVuln01()

    def __init__(self):
        super().__init__(
            required_components=[
                GCSTelemetry(),
                self.sik_auth_vuln.component,
                self.mavlink_vuln.component,
                ControllerHigh(),
                MultiCopterMotor(),
            ],
            # TODO: how to describe what kind of input is needed
            entry_component=GCSTelemetry(),
            vulnerabilities=[self.sik_auth_vuln, self.mavlink_vuln]
        )

        # We want the motor to be powered, but to be doing nothing. This can be described as neither
        # having lift, pitch, or yaw.

        gms = MultiCopterMotorAlgo()
        gms.conditions = [
            gms.v["yaw"] == 0,
            gms.v["pitch"] == 0,
            gms.v["lift"] == 0,
        ]
        self.goal_motor_state = gms

    def is_possible_path(self, path: List[Type[CyberComponentBase]]):
        required_components = [MultiCopterMotor, Telemetry, ControllerHigh]
        for required in required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        for component in state.components:
            if isinstance(component, MultiCopterMotor):
                if not component.powered:
                    return False
            elif isinstance(component, MultiCopterMotor):
                if component != self.goal_motor_state:
                    return False
            elif isinstance(component, Telemetry) and not component.powered:
                return False
            elif isinstance(component, ControllerHigh) and not component.powered:
                return False
        return True
