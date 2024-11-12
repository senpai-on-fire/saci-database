from .ngcrover import NGCRover
from .px4_quadcopter_device import PX4Quadcopter

devices = {
    "NGCRover": NGCRover(),
    "PX4Quadcopter": PX4Quadcopter(),
}