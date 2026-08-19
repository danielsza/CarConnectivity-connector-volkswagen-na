"""
MQTT Token Session — Receives OAuth tokens from a Frida relay via MQTT
instead of performing its own OAuth login flow.

This bypasses Play Integrity enforcement on the /oidc/v1/token endpoint
by using tokens captured from a real Android device running the VW app.

Place in: src/carconnectivity_connectors/volkswagen_na/auth/mqtt_token_session.py
"""

from __future__ import annotations
from typing import TYPE_CHECKING

import json
import logging
import threading
import time

import jwt as pyjwt

from carconnectivity.errors import AuthenticationError, TemporaryAuthenticationError

from carconnectivity_connectors.volkswagen_na.auth.myvw_session import MyVWSession

if TYPE_CHECKING:
    from typing import Optional, Dict, Any

LOG = logging.getLogger("carconnectivity.connectors.volkswagen_na.auth.mqtt")


class MQTTTokenSession(MyVWSession):
    """
    Session that receives tokens from an external MQTT relay (Frida-based)
    instead of performing OAuth login directly.

    The Frida relay captures tokens from the real VW Android app running on
    a rooted device that passes Play Integrity, then publishes them to MQTT.
    This session subscribes to that topic and uses the captured tokens for
    all API calls.
    """

    def __init__(
        self,
        session_user,
        mqtt_host: str = "localhost",
        mqtt_port: int = 1883,
        mqtt_user: Optional[str] = None,
        mqtt_pass: Optional[str] = None,
        mqtt_topic: str = "vw/token_relay",
        country: str = "us",
        **kwargs,
    ) -> None:
        # Initialize parent — we still need client_id, base URLs, etc.
        super().__init__(session_user=session_user, country=country, **kwargs)

        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.mqtt_user = mqtt_user
        self.mqtt_pass = mqtt_pass
        self.mqtt_topic = mqtt_topic

        self._mqtt_client = None
        self._token_event = threading.Event()
        self._mqtt_connected = False
        self._last_mqtt_token_time: float = 0

        self._setup_mqtt()

    def _setup_mqtt(self) -> None:
        """Connect to the MQTT broker and subscribe to the token relay topic."""
        try:
            import paho.mqtt.client as mqtt_lib
        except ImportError:
            raise ImportError(
                "paho-mqtt is required for MQTT token relay. "
                "Install with: pip install paho-mqtt"
            )

        self._mqtt_client = mqtt_lib.Client(
            client_id="carconnectivity-token-consumer",
            protocol=mqtt_lib.MQTTv311,
        )

        if self.mqtt_user:
            self._mqtt_client.username_pw_set(self.mqtt_user, self.mqtt_pass)

        self._mqtt_client.on_connect = self._on_mqtt_connect
        self._mqtt_client.on_message = self._on_mqtt_message
        self._mqtt_client.on_disconnect = self._on_mqtt_disconnect

        try:
            self._mqtt_client.connect(self.mqtt_host, self.mqtt_port)
            self._mqtt_client.loop_start()
            LOG.info("MQTT token consumer connecting to %s:%d", self.mqtt_host, self.mqtt_port)
        except Exception as e:
            LOG.error("Failed to connect to MQTT broker: %s", e)
            raise AuthenticationError(f"Cannot connect to MQTT broker for token relay: {e}")

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._mqtt_connected = True
            client.subscribe(self.mqtt_topic, qos=1)
            LOG.info("MQTT connected, subscribed to %s", self.mqtt_topic)
        else:
            LOG.error("MQTT connection failed with rc=%d", rc)

    def _on_mqtt_disconnect(self, client, userdata, rc):
        self._mqtt_connected = False
        LOG.warning("MQTT disconnected (rc=%d), will auto-reconnect", rc)

    def _on_mqtt_message(self, client, userdata, msg):
        """Process incoming token from the Frida relay."""
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            LOG.error("Invalid MQTT token payload: %s", e)
            return

        access_token = payload.get("access_token")
        if not access_token:
            LOG.debug("MQTT message has no access_token, ignoring")
            return

        # Build OAuthlib-compatible token dict
        new_token: Dict[str, Any] = {
            "access_token": access_token,
            "token_type": payload.get("token_type", "bearer"),
        }
        if "refresh_token" in payload:
            new_token["refresh_token"] = payload["refresh_token"]
        if "id_token" in payload:
            new_token["id_token"] = payload["id_token"]
        if "expires_in" in payload:
            new_token["expires_in"] = int(payload["expires_in"])
        if "scope" in payload:
            new_token["scope"] = payload["scope"]

        # Extract user ID from the JWT sub claim
        try:
            claims = pyjwt.decode(access_token, options={"verify_signature": False})
            sub = claims.get("sub")
            if sub:
                self.metadata["userId"] = sub
                LOG.debug("Extracted user_id (sub) from token: %s", sub[:8])
        except Exception:
            pass

        # Set the token via the parent's setter (handles expires_at calculation)
        self.token = new_token
        self._last_mqtt_token_time = time.time()
        self.last_login = time.time()

        # Signal any waiting threads
        self._token_event.set()

        LOG.info(
            "Token updated from MQTT relay (expires_in=%s, has_refresh=%s)",
            new_token.get("expires_in", "?"),
            "refresh_token" in new_token,
        )

    def login(self):
        """
        Wait for a token from the MQTT relay instead of performing OAuth login.

        Blocks until a token arrives or times out after 120 seconds.
        """
        LOG.info("Waiting for token from MQTT relay on topic '%s'...", self.mqtt_topic)
        self.last_login = time.time()

        if self.access_token and not self.expired:
            LOG.info("Already have a valid token, skipping wait")
            return

        self._token_event.clear()
        if self._token_event.wait(timeout=120):
            LOG.info("Token received from MQTT relay")
        else:
            raise TemporaryAuthenticationError(
                "Timed out waiting for token from MQTT relay. "
                "Ensure the Frida relay (vw_token_relay.py) is running and publishing to "
                f"MQTT topic '{self.mqtt_topic}'"
            )

    def refresh(self) -> None:
        """
        Wait for a fresh token from the MQTT relay instead of calling the
        OIDC refresh endpoint (which requires Play Integrity).

        If a recent token was received (< 60s ago), use it. Otherwise wait
        up to 90 seconds for the relay to publish a new one.
        """
        LOG.info("Token refresh requested — waiting for MQTT relay")

        # If we got a token recently, it might already be fresh
        if self.access_token and not self.expired:
            LOG.info("Current token is still valid, no refresh needed")
            return

        # Request a wake-up from the relay by publishing to cmd topic
        if self._mqtt_client and self._mqtt_connected:
            self._mqtt_client.publish("vw/cmd/wake_app", "", qos=0)
            LOG.info("Published wake_app command to trigger token refresh")

        self._token_event.clear()
        if self._token_event.wait(timeout=90):
            LOG.info("Fresh token received from MQTT relay")
        else:
            LOG.warning("Timed out waiting for fresh token from relay")
            # Don't raise — the parent's request() will try login() next
            raise TemporaryAuthenticationError(
                "Token refresh timed out waiting for MQTT relay"
            )

    def close(self):
        """Clean up MQTT connection."""
        if self._mqtt_client:
            try:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
            except Exception:
                pass
        super().close()
