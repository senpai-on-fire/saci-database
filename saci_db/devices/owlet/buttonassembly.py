"""Auto-generated component for system "button_assembly"."""
from saci.modeling.device.component.cyber import CyberComponentBase

class buttonassembly(CyberComponentBase):
    def __init__(self, **kwargs):
        # TODO: has_external_input?
        super().__init__(**kwargs)
        # TODO: do something more interesting with ports
        
        self.power_button = None
        
        self.arm_button = None
        
        self.charging_port = None
        