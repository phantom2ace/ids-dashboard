document.addEventListener('DOMContentLoaded', () => {
    const mapContainer = document.getElementById('threatMap');
    if (!mapContainer) return;

    // Center map globally
    const map = L.map('threatMap', {
        center: [20, 0],
        zoom: 3,
        zoomControl: false,
        attributionControl: false
    });

    // Enterprise Dark Theme Tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
        maxZoom: 19
    }).addTo(map);

    // Add boundaries (optional)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png', {
        maxZoom: 19,
        pane: 'shadowPane'
    }).addTo(map);

    const getSeverityColor = (severity) => {
        switch(severity?.toUpperCase()) {
            case 'CRITICAL': return '#ef4444'; // Red
            case 'HIGH': return '#f97316'; // Orange
            case 'MEDIUM': return '#eab308'; // Yellow
            default: return '#3b82f6'; // Blue
        }
    };

    // Store markers to avoid duplicates
    const activeMarkers = {};

    const updateMap = async () => {
        try {
            const response = await fetch('/api/threat-map');
            const data = await response.json();
            
            const mapStatus = document.getElementById('mapStatus');
            if (mapStatus) mapStatus.innerHTML = `Active connections: ${data.length} <br> Last update: ${new Date().toLocaleTimeString()}`;

            // Tenant dummy coordinates (US center)
            const tenantLat = 39.8283;
            const tenantLng = -98.5795;

            // Plot tenant
            if (!activeMarkers['tenant']) {
                activeMarkers['tenant'] = L.circleMarker([tenantLat, tenantLng], {
                    radius: 8,
                    fillColor: '#22c55e',
                    color: '#fff',
                    weight: 2,
                    opacity: 1,
                    fillOpacity: 0.8
                }).bindPopup("<b>Protected SOC Tenants</b><br>Global Headquarters").addTo(map);
            }

            data.forEach(loc => {
                const id = `${loc.latitude}-${loc.longitude}`;
                if (!loc.latitude || !loc.longitude) return;

                if (!activeMarkers[id]) {
                    // Create marker
                    const color = getSeverityColor(loc.severity);
                    const marker = L.circleMarker([loc.latitude, loc.longitude], {
                        radius: 5,
                        fillColor: color,
                        color: color,
                        weight: 1,
                        opacity: 1,
                        fillOpacity: 0.8
                    }).bindPopup(`<b>${loc.ip_address}</b><br>Hits: ${loc.total_hits}<br>Last Severity: ${loc.severity}`).addTo(map);

                    activeMarkers[id] = marker;

                    // Draw animated attack line
                    const latlngs = [
                        [loc.latitude, loc.longitude],
                        [tenantLat, tenantLng]
                    ];
                    
                    const polyline = L.polyline(latlngs, {
                        color: color,
                        weight: 1.5,
                        opacity: 0.5,
                        dashArray: '5, 10',
                        className: 'attack-line'
                    }).addTo(map);

                    // Fade line after 5 seconds to simulate "strike"
                    setTimeout(() => {
                        map.removeLayer(polyline);
                    }, 5000);
                }
            });
        } catch (error) {
            console.error('Map update error:', error);
        }
    };

    // Add some CSS for animated lines
    const style = document.createElement('style');
    style.innerHTML = `
        @keyframes dash {
            to { stroke-dashoffset: -20; }
        }
        .attack-line {
            animation: dash 1s linear infinite;
        }
    `;
    document.head.appendChild(style);

    updateMap();
    setInterval(updateMap, 3000); // Frequent updates for warfare visual
});
