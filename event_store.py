"""
In-Memory Event Store for MCP Streamable HTTP Resumability

This event store implements the MCP SDK's EventStore interface to enable
SSE stream resumability. Clients can reconnect and resume from where they
left off using the Last-Event-ID header.

Note: This is an in-memory implementation suitable for development and
single-instance deployments. For production with multiple instances,
use Redis or another persistent store.
"""

import asyncio
import time
import logging
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass, field
from collections import OrderedDict

import mcp.types as types
from mcp.server.streamable_http_manager import EventStore
from mcp.server.streamable_http import EventMessage

logger = logging.getLogger(__name__)


@dataclass
class StoredEvent:
    """A stored SSE event with metadata"""
    event_id: str
    stream_id: str
    message: types.JSONRPCMessage
    created_at: float = field(default_factory=time.time)


class InMemoryEventStore(EventStore):
    """
    In-memory event store implementing the MCP SDK EventStore interface.
    
    Stores events by stream ID, allowing clients to resume from a specific event ID.
    Automatically expires old events to prevent unbounded memory growth.
    """
    
    def __init__(self, max_events_per_stream: int = 1000, event_ttl_seconds: int = 3600):
        """
        Initialize the event store.
        
        Args:
            max_events_per_stream: Maximum events to store per stream
            event_ttl_seconds: Time-to-live for events in seconds (default: 1 hour)
        """
        self._events: dict[str, OrderedDict[str, StoredEvent]] = {}
        self._lock = asyncio.Lock()
        self._max_events = max_events_per_stream
        self._event_ttl = event_ttl_seconds
        self._event_counter = 0
        logger.info(f"InMemoryEventStore initialized (max_events={max_events_per_stream}, ttl={event_ttl_seconds}s)")
    
    def _generate_event_id(self) -> str:
        """Generate a unique event ID"""
        self._event_counter += 1
        return f"{int(time.time() * 1000)}-{self._event_counter}"
    
    async def store_event(self, stream_id: str, message: types.JSONRPCMessage) -> str:
        """
        Store an event for a stream.
        
        Args:
            stream_id: The stream identifier (typically session ID)
            message: The JSON-RPC message to store
            
        Returns:
            The event ID
        """
        async with self._lock:
            if stream_id not in self._events:
                self._events[stream_id] = OrderedDict()
            
            event_id = self._generate_event_id()
            
            self._events[stream_id][event_id] = StoredEvent(
                event_id=event_id,
                stream_id=stream_id,
                message=message
            )
            
            # Trim old events if over limit
            while len(self._events[stream_id]) > self._max_events:
                self._events[stream_id].popitem(last=False)
            
            logger.debug(f"Stored event {event_id} for stream {stream_id}")
            return event_id
    
    async def replay_events_after(
        self,
        last_event_id: str,
        send_callback: Callable[[EventMessage], Awaitable[None]]
    ) -> Optional[str]:
        """
        Replay all events after a specific event ID.
        
        Args:
            last_event_id: The last event ID the client received
            send_callback: Callback to send each event
            
        Returns:
            The stream ID if events were found, None otherwise
        """
        async with self._lock:
            # Find which stream has this event
            target_stream_id = None
            for stream_id, events in self._events.items():
                if last_event_id in events:
                    target_stream_id = stream_id
                    break
            
            if target_stream_id is None:
                logger.warning(f"Event {last_event_id} not found in any stream")
                return None
            
            events = list(self._events[target_stream_id].items())
            
            # Find the index of last_event_id
            found_index = -1
            for i, (eid, _) in enumerate(events):
                if eid == last_event_id:
                    found_index = i
                    break
            
            if found_index == -1:
                return None
            
            # Replay events after the found index
            events_to_replay = events[found_index + 1:]
            
            logger.info(f"Replaying {len(events_to_replay)} events after {last_event_id} for stream {target_stream_id}")
            
            for event_id, stored_event in events_to_replay:
                event_message = EventMessage(
                    event_id=event_id,
                    message=stored_event.message
                )
                await send_callback(event_message)
            
            return target_stream_id
    
    async def cleanup_stream(self, stream_id: str) -> None:
        """Remove all events for a stream"""
        async with self._lock:
            if stream_id in self._events:
                del self._events[stream_id]
                logger.debug(f"Cleaned up events for stream {stream_id}")
    
    async def cleanup_expired(self) -> int:
        """
        Remove expired events from all streams.
        
        Returns:
            Number of events removed
        """
        current_time = time.time()
        removed_count = 0
        
        async with self._lock:
            for stream_id in list(self._events.keys()):
                events = self._events[stream_id]
                expired_ids = [
                    eid for eid, event in events.items()
                    if current_time - event.created_at > self._event_ttl
                ]
                for eid in expired_ids:
                    del events[eid]
                    removed_count += 1
                
                # Remove empty streams
                if not events:
                    del self._events[stream_id]
        
        if removed_count > 0:
            logger.debug(f"Cleaned up {removed_count} expired events")
        
        return removed_count
    
    @property
    def stream_count(self) -> int:
        """Number of active streams"""
        return len(self._events)
    
    @property
    def total_events(self) -> int:
        """Total number of stored events across all streams"""
        return sum(len(events) for events in self._events.values())
