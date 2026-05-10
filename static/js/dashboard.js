document.addEventListener('DOMContentLoaded', () => {
    console.log('IDS Dashboard initialized');
    
    // Theme Switcher Logic
    const themeToggle = document.getElementById('themeToggle');
    const sunIcon = document.getElementById('sunIcon');
    const moonIcon = document.getElementById('moonIcon');
    const html = document.documentElement;

    // Check for saved theme or default to dark
    const savedTheme = localStorage.getItem('theme') || 'dark';
    if (savedTheme === 'dark') {
        html.classList.add('dark');
        sunIcon.classList.remove('hidden');
        moonIcon.classList.add('hidden');
    } else {
        html.classList.remove('dark');
        sunIcon.classList.add('hidden');
        moonIcon.classList.remove('hidden');
    }

    themeToggle.addEventListener('click', () => {
        html.classList.toggle('dark');
        const isDark = html.classList.contains('dark');
        
        if (isDark) {
            sunIcon.classList.remove('hidden');
            moonIcon.classList.add('hidden');
            localStorage.setItem('theme', 'dark');
        } else {
            sunIcon.classList.add('hidden');
            moonIcon.classList.remove('hidden');
            localStorage.setItem('theme', 'light');
        }
    });

    // Sidebar Toggle Logic
    const sidebar = document.getElementById('sidebar');
    const menuBtn = document.getElementById('menuBtn');
    const closeSidebar = document.getElementById('closeSidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');

    const toggleSidebar = () => {
        const isHidden = sidebar.classList.contains('-translate-x-full');
        
        if (isHidden) {
            // Show Sidebar
            sidebar.classList.remove('-translate-x-full');
            sidebar.classList.add('translate-x-0');
            menuBtn.classList.add('hidden'); // Hide Hamburger
            
            if (window.innerWidth >= 1024) {
                sidebar.style.marginLeft = '0';
            } else {
                sidebarOverlay.classList.remove('hidden');
            }
        } else {
            // Hide Sidebar
            sidebar.classList.add('-translate-x-full');
            sidebar.classList.remove('translate-x-0');
            menuBtn.classList.remove('hidden'); // Show Hamburger
            
            if (window.innerWidth >= 1024) {
                sidebar.style.marginLeft = `-${sidebar.offsetWidth}px`;
            } else {
                sidebarOverlay.classList.add('hidden');
            }
        }
    };

    menuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleSidebar();
    });

    if (closeSidebar) {
        closeSidebar.addEventListener('click', toggleSidebar);
    }
    
    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', toggleSidebar);
    }

    // Initial state check
    if (window.innerWidth < 1024) {
        sidebar.classList.add('-translate-x-full');
        sidebar.classList.remove('translate-x-0');
        menuBtn.classList.remove('hidden');
    } else {
        sidebar.classList.add('translate-x-0');
        sidebar.classList.remove('-translate-x-full');
        menuBtn.classList.add('hidden');
    }

    // Fortinet-style System Resource Monitor Simulation
    const updateResources = () => {
        const cpu = Math.floor(Math.random() * 15) + 5; // 5-20%
        const mem = Math.floor(Math.random() * 10) + 40; // 40-50%
        
        const cpuBar = document.getElementById('cpuBar');
        const cpuText = document.getElementById('cpuText');
        const memBar = document.getElementById('memBar');
        const memText = document.getElementById('memText');
        
        if (cpuBar) {
            cpuBar.style.width = `${cpu}%`;
            cpuText.innerText = `${cpu}%`;
            cpuBar.className = `h-full ${cpu > 80 ? 'bg-red-500' : cpu > 50 ? 'bg-yellow-500' : 'bg-green-500'}`;
        }
        
        if (memBar) {
            memBar.style.width = `${mem}%`;
            memText.innerText = `${mem}%`;
        }
        
        // Update Time
        const timeEl = document.getElementById('systemTime');
        if (timeEl) {
            timeEl.innerText = new Date().toLocaleTimeString();
        }
    };

    updateResources();
    setInterval(updateResources, 3000);

    // Threat Map Initialization (Leaflet)
    let map;
    const initMap = () => {
        const mapContainer = document.getElementById('threatMap');
        if (!mapContainer) return;

        // Initialize map centered on world
        map = L.map('threatMap', {
            center: [20, 0],
            zoom: 2,
            zoomControl: false,
            attributionControl: false
        });

        // Dark theme tiles for the map (CartoDB Dark Matter)
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            maxZoom: 19
        }).addTo(map);

        updateThreatMap();
    };

    const updateThreatMap = async () => {
        if (!map) return;

        try {
            const response = await fetch('/api/threat-map');
            const locations = await response.json();

            // Clear existing markers if any (optional, or just keep adding new ones)
            // For a live SOC feel, we can just add new markers and maybe pulse them
            
            locations.forEach(loc => {
                if (loc.latitude && loc.longitude) {
                    const marker = L.circleMarker([loc.latitude, loc.longitude], {
                        radius: 5,
                        fillColor: loc.severity >= 3 ? '#ef4444' : '#f59e0b',
                        color: '#fff',
                        weight: 1,
                        opacity: 1,
                        fillOpacity: 0.8
                    }).addTo(map);

                    marker.bindPopup(`
                        <div class="text-xs font-sans">
                            <p class="font-bold text-red-500 uppercase">${loc.signature}</p>
                            <p class="text-slate-600 mt-1">Source: <b>${loc.src_ip}</b></p>
                            <p class="text-slate-600">Location: <b>${loc.city}, ${loc.country}</b></p>
                        </div>
                    `);
                }
            });
        } catch (error) {
            console.error('Error updating threat map:', error);
        }
    };

    initMap();
    setInterval(updateThreatMap, 15000); // Update map every 15s

    // Example: Fetch alerts every 30 seconds
    const fetchAlerts = async () => {
        try {
            const response = await fetch('/api/alerts');
            const data = await response.json();
            updateAlertTable(data);
        } catch (error) {
            console.error('Error fetching alerts:', error);
        }
    };

    const updateAlertTable = (alerts) => {
        const tbody = document.getElementById('alertTableBody');
        if (!tbody) return;
        
        if (!alerts || alerts.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="py-8 text-center text-slate-500 italic">No live alerts detected</td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = alerts.map(alert => `
            <tr onclick='openAlertDetails(${JSON.stringify(alert).replace(/'/g, "&apos;")})' class="hover:bg-slate-100 dark:hover:bg-slate-700/30 transition-colors cursor-pointer group">
                <td class="py-4 px-4 text-slate-500 dark:text-slate-400 whitespace-nowrap text-[10px] font-mono">
                    ${new Date(alert.timestamp).toLocaleString()}
                </td>
                <td class="py-4 px-4 font-medium">${alert.signature}</td>
                <td class="py-4 px-4">
                    <div class="flex flex-col">
                        <span class="px-2 py-0.5 text-[9px] font-mono bg-blue-900/20 text-blue-400 rounded border border-blue-800/50 w-fit">
                            ${alert.ml_prediction || 'PENDING'}
                        </span>
                        <span class="text-[8px] text-slate-500 mt-1 uppercase">CONFIDENCE: ${Math.floor((alert.confidence || 0) * 100)}%</span>
                    </div>
                </td>
                <td class="py-4 px-4">
                    <span class="status-pill border ${getSeverityClass(String(alert.severity))}">
                        ${alert.severity}
                    </span>
                </td>
                <td class="py-4 px-4 font-mono text-[10px] text-red-400/80 group-hover:text-red-400">
                    ${alert.category || 'N/A'}
                </td>
                <td class="py-4 px-4 font-mono text-[10px] text-slate-400">${alert.src_ip}</td>
            </tr>
        `).join('');
    };

    // Modal Logic
    window.openAlertDetails = (alert) => {
        const modal = document.getElementById('alertModal');
        const content = document.getElementById('modalContent');
        
        content.innerHTML = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-4">
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Source IP</p>
                        <p class="text-lg font-mono text-white">${alert.src_ip}</p>
                    </div>
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Signature</p>
                        <p class="text-lg text-blue-400 font-semibold">${alert.signature}</p>
                    </div>
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Category</p>
                        <p class="text-lg text-red-400 font-mono">${alert.category || 'N/A'}</p>
                    </div>
                </div>
                <div class="space-y-4 bg-[#141820] p-4 rounded border border-slate-800">
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">ML Prediction</p>
                        <p class="text-sm font-bold text-slate-200">${alert.ml_prediction || 'PENDING'}</p>
                    </div>
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Model Confidence</p>
                        <div class="w-full h-1.5 bg-slate-800 rounded-full mt-1">
                            <div class="h-full bg-blue-500 rounded-full" style="width: ${(alert.confidence || 0) * 100}%"></div>
                        </div>
                    </div>
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Severity</p>
                        <p class="text-sm text-orange-400 font-bold uppercase">${alert.severity}</p>
                    </div>
                </div>
            </div>
            <div>
                <p class="text-[10px] text-slate-500 uppercase font-bold mb-2">Raw Feature Vector (NSL-KDD)</p>
                <div class="bg-black/40 p-3 rounded font-mono text-[10px] text-slate-400 break-all border border-slate-800/50">
                    ${alert.payload || 'No raw data available'}
                </div>
            </div>
        `;
        
        modal.classList.remove('hidden');
    };

    window.closeModal = () => {
        document.getElementById('alertModal').classList.add('hidden');
    };

    window.exportAlerts = () => {
        fetch('/api/alerts')
            .then(res => res.json())
            .then(data => {
                if (data.length === 0) return;
                const headers = Object.keys(data[0]).join(',');
                const rows = data.map(row => Object.values(row).join(',')).join('\n');
                const csvContent = "data:text/csv;charset=utf-8," + headers + "\n" + rows;
                const encodedUri = encodeURI(csvContent);
                const link = document.createElement("a");
                link.setAttribute("href", encodedUri);
                link.setAttribute("download", `idssd_alerts_${new Date().getTime()}.csv`);
                document.body.appendChild(link);
                link.click();
            });
    };

    const getSeverityClass = (severity) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'bg-red-200 dark:bg-red-950 text-red-900 dark:text-red-200 border-red-400 dark:border-red-900';
            case 'high': return 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 border-red-200 dark:border-red-500/50';
            case 'medium': return 'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400 border-orange-200 dark:border-orange-500/50';
            default: return 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-500/50';
        }
    };

    fetchAlerts();
    setInterval(fetchAlerts, 10000); // Update every 10 seconds
});

// Global functions for template actions
async function toggleStatus(ip, currentStatus) {
    const newStatus = currentStatus === 'Blocked' ? 'Active' : 'Blocked';
    try {
        const response = await fetch('/api/attackers/toggle-status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, status: newStatus })
        });
        if (response.ok) {
            window.location.reload(); // Refresh to show updated status
        }
    } catch (error) {
        console.error('Error toggling status:', error);
    }
}
