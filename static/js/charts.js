// Initialize charts if elements exist
document.addEventListener('DOMContentLoaded', () => {
    const isDark = () => document.documentElement.classList.contains('dark');
    const getGridColor = () => isDark() ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)';
    const getTextColor = () => isDark() ? '#94a3b8' : '#64748b';

    const charts = {};

    // Helper to fetch and update dashboard charts
    const updateDashboardCharts = () => {
        const lineCtx = document.getElementById('lineChart');
        const barCtx = document.getElementById('barChart');
        const pieCtx = document.getElementById('pieChart');

        if (lineCtx || barCtx || pieCtx) {
            fetch('/api/dashboard-stats')
                .then(res => res.json())
                .then(data => {
                    // Line Chart
                    if (lineCtx) {
                        if (charts.line) charts.line.destroy();
                        charts.line = new Chart(lineCtx, {
                            type: 'line',
                            data: {
                                labels: Object.keys(data.line),
                                datasets: [{
                                    label: 'Alerts',
                                    data: Object.values(data.line),
                                    borderColor: '#3b82f6',
                                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                    tension: 0.4,
                                    fill: true
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: { legend: { display: false } },
                                scales: {
                                    y: { beginAtZero: true, grid: { color: getGridColor() }, ticks: { color: getTextColor() } },
                                    x: { grid: { display: false }, ticks: { color: getTextColor() } }
                                }
                            }
                        });
                    }

                    // Bar Chart
                    if (barCtx) {
                        if (charts.bar) charts.bar.destroy();
                        charts.bar = new Chart(barCtx, {
                            type: 'bar',
                            data: {
                                labels: Object.keys(data.bar),
                                datasets: [{
                                    data: Object.values(data.bar),
                                    backgroundColor: ['#7f1d1d', '#ef4444', '#f59e0b', '#3b82f6'],
                                    borderRadius: 6
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: { legend: { display: false } },
                                scales: {
                                    y: { beginAtZero: true, grid: { color: getGridColor() }, ticks: { color: getTextColor() } },
                                    x: { grid: { display: false }, ticks: { color: getTextColor() } }
                                }
                            }
                        });
                    }

                    // Pie Chart
                    if (pieCtx) {
                        if (charts.pie) charts.pie.destroy();
                        charts.pie = new Chart(pieCtx, {
                            type: 'pie',
                            data: {
                                labels: Object.keys(data.pie),
                                datasets: [{
                                    data: Object.values(data.pie),
                                    backgroundColor: ['#3b82f6', '#ef4444', '#f59e0b', '#10b981'],
                                    borderWidth: 0
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {
                                    legend: {
                                        position: 'bottom',
                                        labels: { color: getTextColor(), boxWidth: 12, padding: 15 }
                                    }
                                }
                            }
                        });
                    }
                });
        }
    };

    updateDashboardCharts();
    setInterval(updateDashboardCharts, 30000); // Update every 30s

    // Analytics Page Charts
    const vectorCtx = document.getElementById('vectorChart');
    const timeCtx = document.getElementById('timeSeriesChart');

    if (vectorCtx || timeCtx) {
        fetch('/api/analytics')
            .then(res => res.json())
            .then(data => {
                if (vectorCtx) {
                    charts.vector = new Chart(vectorCtx, {
                        type: 'pie',
                        data: {
                            labels: Object.keys(data.distribution),
                            datasets: [{
                                data: Object.values(data.distribution),
                                backgroundColor: ['#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6'],
                                borderWidth: 0
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: {
                                    position: 'bottom',
                                    labels: { color: getTextColor() }
                                }
                            }
                        }
                    });
                }

                if (timeCtx) {
                    charts.time = new Chart(timeCtx, {
                        type: 'line',
                        data: {
                            labels: Object.keys(data.timeline),
                            datasets: [{
                                label: 'Attacks',
                                data: Object.values(data.timeline),
                                borderColor: '#8b5cf6',
                                backgroundColor: 'rgba(139, 92, 246, 0.1)',
                                fill: true,
                                tension: 0.4
                            }]
                        },
                        options: {
                            responsive: true,
                            scales: {
                                y: { beginAtZero: true, grid: { color: getGridColor() }, ticks: { color: getTextColor() } },
                                x: { grid: { display: false }, ticks: { color: getTextColor() } }
                            },
                            plugins: {
                                legend: { display: false }
                            }
                        }
                    });
                }
            });
    }

    // Update all charts on theme toggle
    document.getElementById('themeToggle').addEventListener('click', () => {
        setTimeout(() => {
            const gridColor = getGridColor();
            const textColor = getTextColor();

            Object.values(charts).forEach(chart => {
                if (chart.options.scales) {
                    if (chart.options.scales.y) {
                        chart.options.scales.y.grid.color = gridColor;
                        chart.options.scales.y.ticks.color = textColor;
                    }
                    if (chart.options.scales.x) {
                        chart.options.scales.x.ticks.color = textColor;
                    }
                }
                if (chart.options.plugins && chart.options.plugins.legend && chart.options.plugins.legend.labels) {
                    chart.options.plugins.legend.labels.color = textColor;
                }
                chart.update();
            });
        }, 0);
    });
});
