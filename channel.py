"""Basic Pub/Sub implementation"""

from typing import Callable


class Channel(object):
    """
    author - https://dev.to/mandrewcito
    """

    def __init__(self):
        self.subscribers = {}

    def unsubscribe(self, event, callback):
        if event is not None or event != "" and event in self.subscribers.keys():
            self.subscribers[event] = list(
                filter(lambda x: x is not callback, self.subscribers[event])
            )

    def subscribe(self, event: str, callback: Callable):
        if not callable(callback):
            raise ValueError("Callback must be callable")

        if event is None or event == "":
            raise ValueError("Event cant be empty")

        if event not in self.subscribers.keys():
            self.subscribers[event] = [callback]
        else:
            self.subscribers[event].append(callback)

    def publish(self, event, args):
        if event in self.subscribers.keys():
            for callback in self.subscribers[event]:
                callback(args)
