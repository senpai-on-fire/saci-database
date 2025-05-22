"""Auto-generated component for system "fan"."""

from saci.modeling.device.component.cyber import CyberComponentBase


class fan(CyberComponentBase):
    def __init__(self, **kwargs):
        # TODO: has_external_input?
        super().__init__(**kwargs)
        # TODO: do something more interesting with ports

        self.power = None
