from os import system, getuid
from shutil import which
from threading import Lock
from time import time


class _SingletonWrapper:
    """
    A singleton wrapper class. Its instances would be created
    for each decorated class.
    """

    def __init__(self, cls):
        self.__wrapped__ = cls
        self._instance = None

    def __call__(self, *args, **kwargs):
        """Returns a single instance of decorated class"""
        if self._instance is None:
            self._instance = self.__wrapped__(*args, **kwargs)
        return self._instance


def singleton(cls):
    """
    A singleton decorator. Returns a wrapper objects. A call on that object
    returns a single instance object of decorated class. Use the __wrapped__
    attribute to access decorated class directly in unit tests
    """
    return _SingletonWrapper(cls)


@singleton
class NotificationManager:
    def __init__(self, minimum_delay: int = 10):
        self.minimum_delay = minimum_delay
        self.__history = {}
        self.__lock = Lock()

    def show_notification(self, title: str, message: str):
        """
        Shows a notification on screen. Supports macOS notifications and Linux notify-send (but not as root)
        :param title: title of the notification
        :param message: message of the notification
        """
        with self.__lock:
            # Check if the same pair title-message has been printed recently
            last_time_printed = self.__history.get((title, message), -1)
            if time() - last_time_printed < self.minimum_delay:
                return

            if which("osascript"):
                system(f"osascript -e 'display notification \"{message}\" with title \"{title}\"'")
            elif which("notify-send") and getuid() != 0:
                system(f"notify-send '{title}' '{message}'")
            else:
                print(f"[{title}] {message}")

            self.__history[(title, message)] = time()
