"""Sensor-side capture agent (stage F of ARCHITECTURE_HE.md).

Runs on the laptop today and on a Raspberry Pi 5 tomorrow with no
change (Tier 0). Records raw PCAP in a tshark ring buffer, and for each
closed chunk: sha256 -> sign -> upload to the VM ingest API, spooling
locally when the link is down and writing explicit gap records when the
spool overflows. The capture filter excludes the agent's own telemetry
flow (spec section 12.2 layer 0), generated from the same config that
defines the upload target - nothing can be excluded without being
declared.
"""
