from saci.modeling import CPV
from saci.modeling.device import NetworkComponent, ControllerHigh, Device
from saci.modeling.state import GlobalState
from saci_db.vulns.icmp_vuln import IcmpFloodVuln

# Define the CPV for the ICMP Flood Attack
class IcmpFloodCPV(CPV):
    def __init__(self):
        icmp_flood_vuln = IcmpFloodVuln()
        super().__init__(
            required_components=[
                icmp_flood_vuln.component,
                NetworkComponent,
                ControllerHigh,
            ],
            entry_component=NetworkComponent(powered=True),
            vulnerabilities=[icmp_flood_vuln]
        )

    def in_goal_state(self, state: GlobalState):
        # The goal state is the network component being overwhelmed by ICMP traffic
        for component in state.components:
            if isinstance(component, NetworkComponent) and component.protocol_name == "icmp":
                # Check if the network component is overwhelmed by the ICMP flood
                if component.powered and component.is_overwhelmed_by_icmp():
                    # Check the state of the controller
                    controller = next((comp for comp in state.components if isinstance(comp, ControllerHigh)), None)
                    if controller:
                        # Assuming there's an attribute 'emergency_state' that indicates the controller is in an emergency mode
                        return controller.emergency_state
        return False