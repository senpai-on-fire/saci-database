from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (ControllerHigh, CyberComponentBase, TelemetryHigh, Controller)
from saci.modeling.device.motor.steering import SteeringHigh, Steering
from saci.modeling.state import GlobalState
from saci_db.vulns.knowncreds import WifiKnownCredsVuln
from saci_db.vulns.weak_interface_auth_vuln import WeakInterfaceAuthVuln
from saci_db.vulns.noaps import NoAPSVuln


class RollOverCPV(CPV):
    NAME = "The roll-the-rover-over CPV"

    def __init__(self):
        known_creds = WifiKnownCredsVuln()
        weak_authentication = WeakInterfaceAuthVuln()
        no_aps = NoAPSVuln()
        super().__init__(
            required_components=[
                known_creds.component,
                Controller(),
                Steering(),
            ],
            entry_component=TelemetryHigh(),
            vulnerabilities=[known_creds, weak_authentication, no_aps]
        )

    def is_possible_path(self, path: List[CyberComponentBase]):
        required_components = [TelemetryHigh, ControllerHigh, SteeringHigh]
        for required in required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
