from saci.modeling.device import Controller


class PX4Controller(Controller):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
