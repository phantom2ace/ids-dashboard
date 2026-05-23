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
                    // Fortinet-style Radar Ping
                    let pingClass = 'radar-ping-low';
                    const sev = (loc.severity || '').toString().toLowerCase();
                    if (sev === 'critical') pingClass = 'radar-ping-critical';
                    else if (sev === 'high') pingClass = 'radar-ping-high';
                    else if (sev === 'medium') pingClass = 'radar-ping-medium';

                    const icon = L.divIcon({
                        className: 'bg-transparent border-0',
                        html: `<div class="${pingClass}"></div>`,
                        iconSize: [12, 12],
                        iconAnchor: [6, 6]
                    });

                    const marker = L.marker([loc.latitude, loc.longitude], { icon: icon }).addTo(map);

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
    // Phase 13: Real-Time WebSockets Synchronization
    const socket = io();
    
    socket.on('connect', () => {
        console.log('[*] Connected to SOC Real-Time Event Stream');
    });
    
    socket.on('new_event', (data) => {
        console.log('[+] Real-Time Event Received:', data);
        // Instantly refresh the UI when the parser detects a new attack
        fetchData();
    });
    
    socket.on('incident_updated', (data) => {
        console.log('[+] Incident State Changed:', data);
        // Instantly refresh the UI when an analyst updates a ticket
        fetchData();
        
        // If the modal is currently open for this incident, we could optionally
        // refresh the modal content here to prevent stale data.
    });

    const fetchData = async () => {
        try {
            const [incidentsRes, alertsRes] = await Promise.all([
                fetch('/api/incidents'),
                fetch('/api/alerts')
            ]);
            const incidents = await incidentsRes.json();
            const alerts = await alertsRes.json();
            
            updateIncidentTable(incidents);
            updateLiveFeed(alerts);
        } catch (error) {
            console.error('Error fetching data:', error);
        }
    };

    const updateIncidentTable = (incidents) => {
        const tbody = document.getElementById('alertTableBody');
        if (!tbody) return;
        
        if (!incidents || incidents.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="py-8 text-center text-slate-500 italic">No active incidents</td>
                </tr>
            `;
            return;
        }

        // Calculate active critical incidents
        const activeCritical = incidents.filter(a => String(a.severity).toLowerCase() === 'critical' && a.status !== 'RESOLVED' && a.status !== 'FALSE_POSITIVE');
        const widget = document.getElementById('needsAttentionWidget');
        const countSpan = document.getElementById('activeCriticalCount');
        if (widget && countSpan) {
            if (activeCritical.length > 0) {
                countSpan.innerText = activeCritical.length;
                widget.classList.remove('hidden');
                widget.classList.add('flex');
            } else {
                widget.classList.add('hidden');
                widget.classList.remove('flex');
            }
        }

        const getStatusBadge = (status) => {
            switch(status) {
                case 'NEW': return '<span class="px-2 py-0.5 rounded border bg-blue-900/20 text-blue-400 border-blue-800/50">🚨 NEW</span>';
                case 'INVESTIGATING': return '<span class="px-2 py-0.5 rounded border bg-orange-900/20 text-orange-400 border-orange-800/50">👀 INVESTIGATING</span>';
                case 'RESOLVED': return '<span class="px-2 py-0.5 rounded border bg-green-900/20 text-green-400 border-green-800/50">✅ RESOLVED</span>';
                case 'FALSE_POSITIVE': return '<span class="px-2 py-0.5 rounded border bg-slate-800 text-slate-400 border-slate-700">👻 FALSE POSITIVE</span>';
                default: return `<span class="px-2 py-0.5 rounded border bg-blue-900/20 text-blue-400 border-blue-800/50">🚨 OPEN</span>`;
            }
        };

        tbody.innerHTML = incidents.map(incident => `
            <tr onclick='openIncidentDetails(${JSON.stringify(incident).replace(/'/g, "&apos;")})' class="hover:bg-slate-100 dark:hover:bg-slate-700/30 transition-colors cursor-pointer group">
                <td class="py-4 px-4 font-bold text-[10px] text-purple-400 tracking-widest whitespace-nowrap">
                    ${incident.incident_id}
                </td>
                <td class="py-4 px-4 text-slate-500 dark:text-slate-400 whitespace-nowrap text-[10px] font-mono">
                    ${new Date(incident.updated_at).toLocaleString()}
                </td>
                <td class="py-4 px-4">
                    <span class="status-pill border ${getSeverityClass(String(incident.severity))}">
                        ${incident.severity}
                    </span>
                </td>
                <td class="py-4 px-4 font-mono text-[9px] whitespace-nowrap">
                    ${getStatusBadge(incident.status)}
                </td>
                <td class="py-4 px-4 font-mono text-[10px] text-slate-300">
                    <div class="flex items-center space-x-1">
                        <svg class="w-3 h-3 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
                        <span>${incident.assigned_analyst}</span>
                    </div>
                </td>
                <td class="py-4 px-4 font-bold text-[10px] text-blue-500 uppercase tracking-widest whitespace-nowrap">
                    ${incident.org_name || 'Local Sensor'}
                </td>
                <td class="py-4 px-4 font-medium">${incident.title}
                    ${incident.mitre_id && incident.mitre_id !== 'N/A' ? `<br><span class="text-[9px] px-1 py-0.5 rounded bg-blue-900/40 text-blue-400 border border-blue-800/50 mt-1 inline-block">${incident.mitre_id}</span>` : ''}
                </td>
                <td class="py-4 px-4 font-mono text-[10px] text-slate-400">${incident.src_ip}</td>
                <td class="py-4 px-4 font-bold text-[10px] text-slate-300">
                    <span class="bg-slate-800 px-2 py-1 rounded-full">${incident.alert_count}</span>
                </td>
            </tr>
        `).join('');
    };

    const updateLiveFeed = (alerts) => {
        const feed = document.getElementById('liveAlertsFeed');
        if (!feed) return;
        
        feed.innerHTML = alerts.map(alert => `
            <div class="p-3 hover:bg-slate-800/50 transition-colors">
                <div class="flex justify-between items-start mb-1">
                    <span class="text-[9px] text-slate-500 font-mono">${new Date(alert.timestamp).toLocaleTimeString()}</span>
                    <span class="text-[9px] font-bold ${alert.severity === 'Critical' ? 'text-red-500' : 'text-orange-400'} uppercase">${alert.severity}</span>
                </div>
                <div class="text-[10px] text-slate-300 font-medium truncate mb-1" title="${alert.signature}">${alert.signature}</div>
                <div class="flex justify-between items-center text-[9px] font-mono text-slate-500">
                    <span>${alert.src_ip} &rarr; ${alert.dest_ip}</span>
                </div>
            </div>
        `).join('');
    };

    // Modal Logic
    window.openIncidentDetails = async (incident) => {
        const modal = document.getElementById('alertModal');
        const content = document.getElementById('modalContent');
        
        // Fetch timeline logs
        let timelineHTML = '';
        try {
            const res = await fetch(`/api/incidents/${incident.incident_id}/logs`);
            const logs = await res.json();
            
            logs.forEach(log => {
                let color = 'bg-blue-500';
                if (log.action_type === 'CREATION') color = 'bg-red-500';
                else if (log.action_type === 'STATUS_CHANGE') color = 'bg-orange-500';
                else if (log.action_type === 'ASSIGNMENT') color = 'bg-purple-500';
                else if (log.action_type === 'NOTE_ADDED') color = 'bg-green-500';

                timelineHTML += `
                    <div class="relative pl-4">
                        <div class="absolute -left-[5px] top-1 w-2 h-2 rounded-full ${color}"></div>
                        <p class="text-[9px] text-slate-500 font-mono">${log.timestamp} - ${log.details} <span class="text-slate-400">(${log.user})</span></p>
                    </div>
                `;
            });
            
            if (logs.length === 0) {
                timelineHTML = `<div class="relative pl-4"><p class="text-[9px] text-slate-500 font-mono">No logs available.</p></div>`;
            }
        } catch (e) {
            timelineHTML = `<div class="relative pl-4"><p class="text-[9px] text-red-500 font-mono">Failed to load timeline.</p></div>`;
        }

        content.innerHTML = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-4">
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Source IP</p>
                        <p class="text-lg font-mono text-white">${incident.src_ip}</p>
                    </div>
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Incident Title</p>
                        <p class="text-lg text-blue-400 font-semibold">${incident.title}</p>
                    </div>
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Incident ID</p>
                        <p class="text-md text-purple-400 font-mono">${incident.incident_id}</p>
                    </div>
                </div>
                <div class="space-y-4 bg-[#141820] p-4 rounded border border-slate-800">
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Threat Intelligence</p>
                        
                        <!-- MITRE ATT&CK Mapping -->
                        <div class="mt-2 bg-[#0a0c10] p-2 rounded border border-slate-700/50 flex flex-col space-y-1">
                            <p class="text-[9px] text-slate-500 uppercase font-bold tracking-widest">MITRE ATT&CK®</p>
                            <p class="text-xs text-blue-400 font-mono">${incident.mitre_id || 'N/A'} - <span class="text-slate-300 font-sans">${incident.mitre_tactic || 'Unknown'}</span></p>
                        </div>
                    </div>
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Correlated Alerts</p>
                        <p class="text-sm font-bold text-slate-200">${incident.alert_count} Alerts Clustered</p>
                    </div>
                    <div>
                        <p class="text-[10px] text-slate-500 uppercase font-bold">Severity</p>
                        <p class="text-sm text-orange-400 font-bold uppercase">${incident.severity}</p>
                    </div>
                </div>
            </div>
            
            <!-- AI Incident Response Playbook -->
            <div class="mt-6 border-t border-slate-800 pt-4">
                <div class="flex items-center space-x-2 mb-3">
                    <div class="w-2 h-2 rounded-full bg-purple-500 animate-pulse"></div>
                    <p class="text-[10px] text-purple-400 uppercase font-bold tracking-widest">AI Analyst Recommendation Playbook</p>
                </div>
                <div class="bg-purple-900/10 border border-purple-800/30 p-4 rounded-lg">
                    <p class="text-sm text-slate-300 leading-relaxed">${incident.recommendation || 'No specific automated playbook available. Investigate manually.'}</p>
                </div>
            </div>

            <!-- Investigation Timeline -->
            <div class="mt-6 border-t border-slate-800 pt-4">
                <p class="text-[10px] text-slate-500 uppercase font-bold mb-3">Orchestration Timeline</p>
                <div class="flex flex-col space-y-4 pl-2 border-l-2 border-slate-700/50" id="modalTimelineFeed">
                    ${timelineHTML}
                </div>
            </div>

            <!-- Analyst Notes System -->
            <div class="mt-6 border-t border-slate-800 pt-4">
                <p class="text-[10px] text-slate-500 uppercase font-bold mb-2">Analyst Investigation</p>
                <div class="flex flex-col space-y-3">
                    <div class="flex space-x-6 items-center">
                        <div class="flex items-center space-x-2">
                            <label class="text-xs text-slate-400">Status:</label>
                            <select id="modalStatusSelect" class="bg-[#141820] text-xs text-slate-200 border border-slate-700 rounded p-1 outline-none focus:border-blue-500 transition-colors">
                                <option value="NEW" ${incident.status === 'NEW' ? 'selected' : ''}>🚨 NEW</option>
                                <option value="INVESTIGATING" ${incident.status === 'INVESTIGATING' ? 'selected' : ''}>👀 INVESTIGATING</option>
                                <option value="ESCALATED" ${incident.status === 'ESCALATED' ? 'selected' : ''}>🛡️ ESCALATED</option>
                                <option value="RESOLVED" ${incident.status === 'RESOLVED' ? 'selected' : ''}>✅ RESOLVED</option>
                                <option value="FALSE_POSITIVE" ${incident.status === 'FALSE_POSITIVE' ? 'selected' : ''}>👻 FALSE POSITIVE</option>
                            </select>
                        </div>
                        <div class="flex items-center space-x-2">
                            <label class="text-xs text-slate-400">Assign To:</label>
                            <select id="modalAnalystSelect" class="bg-[#141820] text-xs text-slate-200 border border-slate-700 rounded p-1 outline-none focus:border-blue-500 transition-colors">
                                <option value="Unassigned" ${incident.assigned_analyst === 'Unassigned' ? 'selected' : ''}>Unassigned</option>
                                <option value="Alice (L1)" ${incident.assigned_analyst === 'Alice (L1)' ? 'selected' : ''}>Alice (L1 Analyst)</option>
                                <option value="Texin (L2)" ${incident.assigned_analyst === 'Texin (L2)' ? 'selected' : ''}>Texin (L2 Escalation)</option>
                                <option value="SOC Lead" ${incident.assigned_analyst === 'SOC Lead' ? 'selected' : ''}>SOC Lead</option>
                            </select>
                        </div>
                    </div>
                    <textarea id="modalNotesText" class="w-full bg-[#141820] border border-slate-700 rounded p-2 text-xs text-slate-300 outline-none focus:border-blue-500 transition-colors" rows="3" placeholder="Add investigation notes...">${incident.analyst_notes || ''}</textarea>
                    <button onclick="saveAnalystNotes('${incident.incident_id}')" class="self-end px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase rounded transition-colors shadow-lg">Save Case Details</button>
                </div>
            </div>
        `;
        
        modal.classList.remove('hidden');
    };

    window.closeModal = () => {
        document.getElementById('alertModal').classList.add('hidden');
    };

    window.saveAnalystNotes = async (incidentId) => {
        const status = document.getElementById('modalStatusSelect').value;
        const analyst = document.getElementById('modalAnalystSelect').value;
        const notes = document.getElementById('modalNotesText').value;

        try {
            const res = await fetch(`/api/incidents/${incidentId}/update`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ status, analyst, notes })
            });
            if (res.ok) {
                closeModal();
                fetchData(); // refresh table instantly
            } else {
                alert('Failed to update case details.');
            }
        } catch (error) {
            console.error('Error saving notes:', error);
        }
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

    fetchData();
    setInterval(fetchData, 60000); // Fallback sync every 60 seconds (WebSockets handle real-time)
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

// Simulate PCAP export for demonstration
function exportPcap() {
    const timestamp = new Date().getTime();
    const mockPcapData = "d4c3b2a1020004000000000000000000ffff000001000000..."; // Mock magic number
    const blob = new Blob([mockPcapData], { type: 'application/vnd.tcpdump.pcap' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `alert_${timestamp}.pcap`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}
