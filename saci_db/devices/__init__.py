from .ngcrover import NGCRover
from .px4_quadcopter_device import PX4Quadcopter

devices = {
    "ngcrover": NGCRover(),
    "px4quadcopter": PX4Quadcopter(),
}