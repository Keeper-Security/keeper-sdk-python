"""Generic observer/pub-sub pattern implementation."""

from typing import Optional, TypeVar, Generic, Callable, List

M = TypeVar('M')


class FanOut(Generic[M]):
    """Generic fan-out/publish-subscribe pattern for distributing messages to multiple callbacks."""

    def __init__(self) -> None:
        self._callbacks: List[Callable[[M], Optional[bool]]] = []
        self._is_completed = False

    @property
    def is_completed(self):
        return self._is_completed

    def push(self, message: M) -> None:
        """Push a message to all registered callbacks.

        Callbacks that return True or raise exceptions are automatically removed.
        """
        if self._is_completed:
            return
        to_remove = []
        for i, cb in enumerate(self._callbacks):
            try:
                rs = cb(message)
                if isinstance(rs, bool) and rs is True:
                    to_remove.append(i)
            except Exception:
                to_remove.append(i)
        self._remove_indexes(to_remove)

    def register_callback(self, callback: Callable[[M], Optional[bool]]) -> None:
        """Register a callback to receive pushed messages."""
        if self._is_completed:
            return
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[M], Optional[bool]]) -> None:
        """Remove a specific callback."""
        if self._is_completed:
            return
        to_remove = []
        for i, cb in enumerate(self._callbacks):
            if cb == callback:
                to_remove.append(i)
        self._remove_indexes(to_remove)

    def remove_all(self):
        """Remove all registered callbacks."""
        self._callbacks.clear()

    def _remove_indexes(self, to_remove: List[int]):
        while to_remove:
            idx = to_remove.pop()
            if 0 <= idx < len(self._callbacks):
                del self._callbacks[idx]

    def shutdown(self):
        """Shutdown the FanOut, marking it as completed and removing all callbacks."""
        self._is_completed = True
        self._callbacks.clear()
