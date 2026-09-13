import { useMemo } from "react";
import { MapContainer, TileLayer, CircleMarker, Polyline, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";

/**
 * Renders the email's relay path on a map.
 *
 * Props:
 *   hopPath - array from geolocation.build_hop_path() on the backend:
 *     [{ ip, country, city, lat, lon, org, flagged }, ...]
 *     already ordered oldest -> newest (origin -> your inbox).
 *
 * Drop this in next to wherever you already render the risk score /
 * indicators panel - it doesn't require any other layout changes.
 *
 * Requires: npm install leaflet react-leaflet
 */
export default function HopMap({ hopPath }) {
  const positions = useMemo(
    () => hopPath.map((hop) => [hop.lat, hop.lon]),
    [hopPath]
  );

  if (!hopPath || hopPath.length === 0) {
    return (
      <div style={styles.empty}>
        No relay path could be resolved for this email.
      </div>
    );
  }

  const center = positions[Math.floor(positions.length / 2)];

  return (
    <div style={styles.wrapper}>
      <div style={styles.legend}>
        <span style={styles.legendItem}>
          <span style={{ ...styles.dot, background: "#3fa9f5" }} /> Normal hop
        </span>
        <span style={styles.legendItem}>
          <span style={{ ...styles.dot, background: "#f54260" }} /> Flagged hop
        </span>
      </div>

      <MapContainer
        center={center}
        zoom={3}
        style={{ height: "420px", width: "100%", borderRadius: "12px" }}
        scrollWheelZoom={false}
      >
        <TileLayer
          attribution='&copy; OpenStreetMap contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        <Polyline
          positions={positions}
          pathOptions={{ color: "#8888aa", weight: 2, dashArray: "6 6" }}
        />

        {hopPath.map((hop, index) => (
          <CircleMarker
            key={`${hop.ip}-${index}`}
            center={[hop.lat, hop.lon]}
            radius={hop.flagged ? 9 : 6}
            pathOptions={{
              color: hop.flagged ? "#f54260" : "#3fa9f5",
              fillColor: hop.flagged ? "#f54260" : "#3fa9f5",
              fillOpacity: 0.85,
            }}
          >
            <Popup>
              <strong>Hop {index + 1}</strong><br />
              {hop.city ? `${hop.city}, ` : ""}{hop.country || "Unknown location"}<br />
              IP: {hop.ip}<br />
              {hop.org && <>Org: {hop.org}<br /></>}
              {hop.flagged && <span style={{ color: "#f54260" }}>Flagged as suspicious</span>}
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}

const styles = {
  wrapper: { display: "flex", flexDirection: "column", gap: "8px" },
  legend: { display: "flex", gap: "16px", fontSize: "13px", color: "#ccc" },
  legendItem: { display: "flex", alignItems: "center", gap: "6px" },
  dot: { width: "10px", height: "10px", borderRadius: "50%", display: "inline-block" },
  empty: {
    padding: "24px",
    textAlign: "center",
    color: "#999",
    border: "1px dashed #444",
    borderRadius: "12px",
  },
};
