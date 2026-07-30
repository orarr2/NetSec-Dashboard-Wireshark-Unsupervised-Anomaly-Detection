"""Geo map report - plots Wigle-located access points on a Leaflet map.

Stage YA. Turns BSSIDs the capture saw, once Wigle has located them, into
a standalone HTML map with a marker per AP (SSID, observed RSSI and the
distance the pipeline's own path-loss model estimates). It is a report
file opened in a normal browser, so it may load Leaflet + OpenStreetMap
tiles from their CDNs (this needs internet to render, like any web map);
nothing is sent anywhere - the points are embedded in the file.

render() takes already-prepared points so it is pure and testable; the
worker assembles the points (Wigle lookups) and calls it.
"""
import html as _html
import json


def render(points, out_path, title="NetSec - located access points"):
    """points: [{"bssid","ssid","lat","lon","rssi","distance_m"}...].
    Writes a self-contained HTML map to out_path and returns it. Points
    without lat/lon are dropped (nothing to place)."""
    placed = [p for p in points
              if isinstance(p.get("lat"), (int, float))
              and isinstance(p.get("lon"), (int, float))]
    data_json = json.dumps(placed)
    center = ([placed[0]["lat"], placed[0]["lon"]] if placed else [0, 0])
    zoom = 15 if placed else 2
    empty_note = ("" if placed else
                  "<p style='padding:12px;font-family:sans-serif'>No "
                  "geolocated access points for this session (no Wigle "
                  "matches, or Wigle enrichment is disabled).</p>")
    doc = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>{_html.escape(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
  href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>html,body,#map{{height:100%;margin:0}}
.leaflet-popup-content{{font-family:sans-serif;font-size:13px}}</style>
</head><body>{empty_note}<div id="map"></div>
<script>
const PTS = {data_json};
const map = L.map('map').setView({center}, {zoom});
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',
  {{maxZoom: 19, attribution: '&copy; OpenStreetMap'}}).addTo(map);
const bounds = [];
for (const p of PTS) {{
  const m = L.marker([p.lat, p.lon]).addTo(map);
  const rssi = (p.rssi != null) ? p.rssi + ' dBm' : 'n/a';
  const dist = (p.distance_m != null) ? p.distance_m + ' m' : 'n/a';
  m.bindPopup('<b>' + (p.ssid || '(hidden SSID)') + '</b><br>' +
    (p.bssid || '') + '<br>RSSI: ' + rssi + '<br>~distance: ' + dist);
  bounds.push([p.lat, p.lon]);
}}
if (bounds.length) map.fitBounds(bounds, {{padding: [40, 40]}});
</script></body></html>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path
