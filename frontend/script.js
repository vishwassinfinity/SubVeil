/**
 * SubVeil - Cyber Intelligence Dashboard
 * Enhanced JavaScript with professional UX
 */

// ==================== Configuration ====================
const CONFIG = {
    API_BASE: 'http://localhost:8000/api',
    TOAST_DURATION: 4000,
    ANIMATION_DURATION: 300,
    STORAGE_KEY: 'subveil_stats'
};

// ==================== State Management ====================
const state = {
    isLoading: false,
    isDeepScanning: false,
    currentView: 'networkAnalysisView',
    stats: {
        scansToday: 0,
        threatsFound: 0,
        urlsAnalyzed: 0
    }
};

// ==================== DOM Elements ====================
const elements = {
    // Toast
    toastContainer: document.getElementById('toastContainer'),
    
    // Mobile menu
    mobileMenuToggle: document.getElementById('mobileMenuToggle'),
    sidebar: document.getElementById('sidebar'),
    
    // URL Analysis
    urlInput: document.getElementById('urlInput'),
    extractBtn: document.getElementById('extractBtn'),
    clearBtn: document.getElementById('clearBtn'),
    loadingOverlay: document.getElementById('loadingOverlay'),
    errorMessage: document.getElementById('errorMessage'),
    errorText: document.getElementById('errorText'),
    resultsArea: document.getElementById('resultsArea'),
    targetUrl: document.getElementById('targetUrl'),
    dataGrid: document.getElementById('dataGrid'),
    
    // Trust Score
    scoreRing: document.getElementById('scoreRing'),
    trustScore: document.getElementById('trustScore'),
    riskBadge: document.getElementById('riskBadge'),
    riskText: document.getElementById('riskText'),
    registrar: document.getElementById('registrar'),
    domainAge: document.getElementById('domainAge'),
    httpsStatus: document.getElementById('httpsStatus'),
    ipAddress: document.getElementById('ipAddress'),
    
    // Deep Scan
    deepScanInput: document.getElementById('deepScanInput'),
    deepScanBtn: document.getElementById('deepScanBtn'),
    deepClearBtn: document.getElementById('deepClearBtn'),
    deepScanLoading: document.getElementById('deepScanLoading'),
    deepScanResults: document.getElementById('deepScanResults'),
    deepScanGrid: document.getElementById('deepScanGrid'),
    gradeCircle: document.getElementById('gradeCircle'),
    scanTarget: document.getElementById('scanTarget'),
    findingsList: document.getElementById('findingsList'),
    
    // Stats
    scansToday: document.getElementById('scansToday'),
    threatsFound: document.getElementById('threatsFound'),
    urlsAnalyzed: document.getElementById('urlsAnalyzed')
};

// ==================== Utility Functions ====================

/**
 * Validate URL format
 */
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
        return false;
    }
}

/**
 * Format URL for display
 */
function formatUrl(url) {
    try {
        const parsed = new URL(url);
        return parsed.hostname;
    } catch {
        return url;
    }
}

/**
 * Debounce function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ==================== Toast Notifications ====================

/**
 * Show toast notification
 */
function showToast(type, title, message, duration = CONFIG.TOAST_DURATION) {
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ'}</span>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
        <button class="toast-close" aria-label="Close notification">×</button>
    `;

    elements.toastContainer.appendChild(toast);

    // Close button handler
    const closeBtn = toast.querySelector('.toast-close');
    closeBtn.addEventListener('click', () => removeToast(toast));

    // Auto remove
    setTimeout(() => removeToast(toast), duration);
}

/**
 * Remove toast with animation
 */
function removeToast(toast) {
    if (!toast || !toast.parentNode) return;
    
    toast.classList.add('toast-exit');
    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 300);
}

// ==================== Navigation ====================

/**
 * Initialize navigation
 */
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const viewId = item.dataset.view;
            switchView(viewId, item);
        });
    });
}

/**
 * Switch between views
 */
function switchView(viewId, navItem) {
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        item.removeAttribute('aria-current');
    });
    
    if (navItem) {
        navItem.classList.add('active');
        navItem.setAttribute('aria-current', 'page');
    }
    
    // Update views
    document.querySelectorAll('.view-container').forEach(view => {
        view.classList.remove('active');
    });
    
    const targetView = document.getElementById(viewId);
    if (targetView) {
        targetView.classList.add('active');
        state.currentView = viewId;
    }
    
    // Close mobile menu
    elements.sidebar.classList.remove('open');
}

/**
 * Initialize mobile menu
 */
function initMobileMenu() {
    elements.mobileMenuToggle.addEventListener('click', () => {
        elements.sidebar.classList.toggle('open');
    });
    
    // Close on outside click
    document.addEventListener('click', (e) => {
        if (window.innerWidth <= 768 &&
            !elements.sidebar.contains(e.target) &&
            !elements.mobileMenuToggle.contains(e.target)) {
            elements.sidebar.classList.remove('open');
        }
    });
}

// ==================== Stats Management ====================

/**
 * Load stats from localStorage
 */
function loadStats() {
    try {
        const saved = localStorage.getItem(CONFIG.STORAGE_KEY);
        if (saved) {
            const data = JSON.parse(saved);
            // Reset if it's a new day
            const today = new Date().toDateString();
            if (data.date !== today) {
                state.stats = { scansToday: 0, threatsFound: 0, urlsAnalyzed: 0 };
            } else {
                state.stats = data.stats || state.stats;
            }
        }
    } catch (e) {
        console.error('Error loading stats:', e);
    }
    updateStatsDisplay();
}

/**
 * Save stats to localStorage
 */
function saveStats() {
    try {
        localStorage.setItem(CONFIG.STORAGE_KEY, JSON.stringify({
            date: new Date().toDateString(),
            stats: state.stats
        }));
    } catch (e) {
        console.error('Error saving stats:', e);
    }
}

/**
 * Update stats display
 */
function updateStatsDisplay() {
    elements.scansToday.textContent = state.stats.scansToday;
    elements.threatsFound.textContent = state.stats.threatsFound;
    elements.urlsAnalyzed.textContent = state.stats.urlsAnalyzed;
}

/**
 * Increment scan count
 */
function incrementScan() {
    state.stats.scansToday++;
    state.stats.urlsAnalyzed++;
    saveStats();
    updateStatsDisplay();
}

/**
 * Increment threat count
 */
function incrementThreats(count = 1) {
    state.stats.threatsFound += count;
    saveStats();
    updateStatsDisplay();
}

// ==================== URL Analysis ====================

/**
 * Initialize URL analysis
 */
function initUrlAnalysis() {
    // Analyze button
    elements.extractBtn.addEventListener('click', handleUrlAnalysis);
    
    // Clear button
    elements.clearBtn.addEventListener('click', clearUrlAnalysis);
    
    // Enter key in input
    elements.urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleUrlAnalysis();
        }
    });
    
    // Input validation feedback
    elements.urlInput.addEventListener('input', debounce(() => {
        const value = elements.urlInput.value.trim();
        if (value && !isValidUrl(value)) {
            elements.urlInput.classList.add('error');
        } else {
            elements.urlInput.classList.remove('error');
        }
    }, 300));
}

/**
 * Handle URL analysis
 */
async function handleUrlAnalysis() {
    const url = elements.urlInput.value.trim();
    
    // Validation
    if (!url) {
        showToast('warning', 'Input Required', 'Please enter a URL to analyze');
        elements.urlInput.focus();
        return;
    }
    
    if (!isValidUrl(url)) {
        showToast('error', 'Invalid URL', 'Please enter a valid URL starting with http:// or https://');
        elements.urlInput.classList.add('error');
        return;
    }
    
    elements.urlInput.classList.remove('error');
    elements.urlInput.classList.add('success');
    
    // Show loading
    setLoading(true);
    hideError();
    hideResults();
    
    try {
        const response = await fetch(`${CONFIG.API_BASE}/extract`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const responseData = await response.json();
        
        // Extract the actual data from API response (data is nested under 'data' key)
        const extractedData = responseData.data || responseData;
        
        // Flatten WHOIS data into the main object for easy access
        const flatData = {
            ...extractedData,
            // Map domain_name to domain for display
            domain: extractedData.domain_name || extractedData.domain,
            // Extract WHOIS data if available
            ...(extractedData.whois || {})
        };
        
        const score = flatData.trust_score ?? flatData.score ?? 75;
        
        incrementScan();
        displayResults(flatData, url);
        updateTrustScore(flatData);
        
        // Save to history
        saveToHistory(url, score, 'quick');
        
        showToast('success', 'Analysis Complete', `Successfully analyzed ${formatUrl(url)}`);
        
    } catch (error) {
        console.error('Analysis error:', error);
        showError('Failed to analyze URL. Please check the backend server is running.');
        showToast('error', 'Analysis Failed', error.message);
    } finally {
        setLoading(false);
        elements.urlInput.classList.remove('success');
    }
}

/**
 * Set loading state
 */
function setLoading(loading) {
    state.isLoading = loading;
    elements.loadingOverlay.classList.toggle('active', loading);
    elements.extractBtn.disabled = loading;
    elements.urlInput.disabled = loading;
}

/**
 * Show error message
 */
function showError(message) {
    elements.errorText.textContent = message;
    elements.errorMessage.classList.add('active');
}

/**
 * Hide error message
 */
function hideError() {
    elements.errorMessage.classList.remove('active');
}

/**
 * Hide results
 */
function hideResults() {
    elements.resultsArea.classList.remove('active');
}

/**
 * Clear URL analysis
 */
function clearUrlAnalysis() {
    elements.urlInput.value = '';
    elements.urlInput.classList.remove('error', 'success');
    hideError();
    hideResults();
    resetTrustScore();
    elements.urlInput.focus();
}

/**
 * Display analysis results
 */
function displayResults(data, url) {
    elements.targetUrl.textContent = url;
    
    const fields = [
        { key: 'domain', label: 'Domain', icon: '🌐' },
        { key: 'domain_name', label: 'Domain Name', icon: '🌐' },
        { key: 'subdomain', label: 'Subdomain', icon: '🔗' },
        { key: 'tld', label: 'TLD', icon: '🏷️' },
        { key: 'ip_address', label: 'IP Address', icon: '📍' },
        { key: 'protocol', label: 'Protocol', icon: '🔒' },
        { key: 'secure', label: 'Secure Connection', icon: '🛡️' },
        { key: 'port', label: 'Port', icon: '🔌' },
        { key: 'path', label: 'Path', icon: '📁' },
        { key: 'file_name', label: 'File Name', icon: '📄' },
        { key: 'query_params', label: 'Query Parameters', icon: '❓' },
        { key: 'fragment', label: 'Fragment', icon: '#️⃣' },
        { key: 'registrar', label: 'Registrar', icon: '🏢' },
        { key: 'organization', label: 'Organization', icon: '🏛️' },
        { key: 'domain_age', label: 'Domain Age', icon: '📅' },
        { key: 'creation_date', label: 'Created', icon: '📆' },
        { key: 'expiry_date', label: 'Expires', icon: '⏰' },
        { key: 'updated_date', label: 'Last Updated', icon: '🔄' },
        { key: 'trust_score', label: 'Trust Score', icon: '⭐' },
        { key: 'risk_level', label: 'Risk Level', icon: '⚠️' },
        { key: 'name_servers', label: 'Name Servers', icon: '🖥️' },
        { key: 'server', label: 'Server', icon: '🖥️' }
    ];
    
    let html = '';
    const displayedValues = new Set(); // Track displayed values to avoid duplicates
    
    fields.forEach(field => {
        let value = data[field.key];
        
        // Skip if value is empty, undefined, 'None', 'Not Available', or already displayed
        if (value === undefined || value === null || value === '' || 
            value === 'None' || value === 'Not Available' || value === 'N/A') {
            return;
        }
        
        // Skip domain_name if we already have domain (avoid duplicates)
        if (field.key === 'domain_name' && data.domain) {
            return;
        }
        
        // Handle arrays (like name_servers)
        if (Array.isArray(value)) {
            if (value.length === 0) return;
            value = value.join(', ');
        }
        
        // Handle objects
        if (typeof value === 'object') {
            value = JSON.stringify(value, null, 2);
        }
        
        // Skip if this exact value was already displayed
        const valueKey = `${field.key}:${value}`;
        if (displayedValues.has(valueKey)) return;
        displayedValues.add(valueKey);
        
        // Determine styling based on field type
        let extraClass = '';
        if (field.key === 'protocol') {
            extraClass = value.toLowerCase() === 'https' ? 'secure' : 'insecure';
        } else if (field.key === 'secure') {
            extraClass = value === 'Yes' ? 'secure' : 'insecure';
        } else if (field.key === 'risk_level') {
            const riskLower = value.toLowerCase();
            if (riskLower === 'low') extraClass = 'secure';
            else if (riskLower === 'medium') extraClass = 'warning';
            else if (riskLower === 'high' || riskLower === 'critical') extraClass = 'insecure';
        } else if (field.key === 'trust_score') {
            const score = parseInt(value);
            if (score >= 75) extraClass = 'secure';
            else if (score >= 50) extraClass = 'warning';
            else extraClass = 'insecure';
        }
        
        html += `
            <div class="data-card">
                <div class="data-label">${field.icon} ${field.label}</div>
                <div class="data-value ${extraClass}">${value}</div>
            </div>
        `;
    });
    
    // Add a message if no data was displayed
    if (!html) {
        html = '<div class="data-card"><div class="data-label">ℹ️ Info</div><div class="data-value">No detailed information available</div></div>';
    }
    
    elements.dataGrid.innerHTML = html;
    elements.resultsArea.classList.add('active');
}

/**
 * Update trust score display
 */
function updateTrustScore(data) {
    const score = data.trust_score ?? data.score ?? 75;
    const circumference = 2 * Math.PI * 42;
    const offset = circumference - (score / 100) * circumference;
    
    // Animate score ring
    elements.scoreRing.style.strokeDasharray = circumference;
    elements.scoreRing.style.strokeDashoffset = circumference;
    
    setTimeout(() => {
        elements.scoreRing.style.strokeDashoffset = offset;
    }, 100);
    
    // Animate score number
    animateNumber(elements.trustScore, 0, score, 1500);
    
    // Update color based on score
    let color, riskClass, riskText;
    if (score >= 80) {
        color = '#10b981';
        riskClass = 'risk-low';
        riskText = 'Low Risk';
    } else if (score >= 50) {
        color = '#f59e0b';
        riskClass = 'risk-medium';
        riskText = 'Medium Risk';
    } else {
        color = '#ef4444';
        riskClass = 'risk-high';
        riskText = 'High Risk';
        incrementThreats();
    }
    
    elements.scoreRing.style.stroke = color;
    elements.trustScore.style.color = color;
    elements.riskBadge.className = `risk-badge ${riskClass}`;
    elements.riskText.textContent = riskText;
    
    // Update WHOIS info
    elements.registrar.textContent = data.registrar || '—';
    elements.domainAge.textContent = data.domain_age || '—';
    elements.httpsStatus.textContent = data.protocol?.toUpperCase() || '—';
    elements.ipAddress.textContent = data.ip_address || '—';
}

/**
 * Reset trust score display
 */
function resetTrustScore() {
    const circumference = 2 * Math.PI * 42;
    elements.scoreRing.style.strokeDashoffset = circumference;
    elements.trustScore.textContent = '--';
    elements.trustScore.style.color = '';
    elements.riskBadge.className = 'risk-badge risk-unknown';
    elements.riskText.textContent = 'Awaiting Analysis';
    elements.registrar.textContent = '—';
    elements.domainAge.textContent = '—';
    elements.httpsStatus.textContent = '—';
    elements.ipAddress.textContent = '—';
}

/**
 * Animate number counting
 */
function animateNumber(element, start, end, duration) {
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing function
        const easeOutCubic = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (end - start) * easeOutCubic);
        
        element.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

// ==================== Deep Scan ====================

/**
 * Initialize deep scan
 */
function initDeepScan() {
    elements.deepScanBtn.addEventListener('click', handleDeepScan);
    elements.deepClearBtn.addEventListener('click', clearDeepScan);
    
    elements.deepScanInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleDeepScan();
        }
    });
}

/**
 * Handle deep scan
 */
async function handleDeepScan() {
    const url = elements.deepScanInput.value.trim();
    
    if (!url) {
        showToast('warning', 'Input Required', 'Please enter a URL to scan');
        elements.deepScanInput.focus();
        return;
    }
    
    if (!isValidUrl(url)) {
        showToast('error', 'Invalid URL', 'Please enter a valid URL');
        return;
    }
    
    // Show loading
    state.isDeepScanning = true;
    elements.deepScanLoading.style.display = 'flex';
    elements.deepScanResults.style.display = 'none';
    elements.deepScanBtn.disabled = true;
    elements.deepScanInput.disabled = true;
    
    showToast('info', 'Deep Scan Started', `Scanning ${formatUrl(url)}...`);
    
    try {
        const response = await fetch(`${CONFIG.API_BASE}/deep-scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const responseData = await response.json();
        
        // Extract the actual data from API response (data is nested under 'data' key)
        const data = responseData.data || responseData;
        
        incrementScan();
        const grade = displayDeepScanResults(data, url);
        
        // Calculate score from grade for history
        const gradeScores = { 'A': 95, 'B': 82, 'C': 70, 'D': 55, 'F': 30 };
        const score = gradeScores[grade] || 50;
        
        // Save to history
        saveToHistory(url, score, 'deep');
        
        showToast('success', 'Deep Scan Complete', `Analysis of ${formatUrl(url)} finished`);
        
    } catch (error) {
        console.error('Deep scan error:', error);
        showToast('error', 'Scan Failed', 'Could not complete deep scan. Check backend server.');
        elements.deepScanLoading.style.display = 'none';
    } finally {
        state.isDeepScanning = false;
        elements.deepScanBtn.disabled = false;
        elements.deepScanInput.disabled = false;
    }
}

/**
 * Clear deep scan
 */
function clearDeepScan() {
    elements.deepScanInput.value = '';
    elements.deepScanLoading.style.display = 'none';
    elements.deepScanResults.style.display = 'none';
    elements.deepScanGrid.innerHTML = '';
    elements.findingsList.innerHTML = '';
    elements.deepScanInput.focus();
}

/**
 * Display deep scan results
 */
function displayDeepScanResults(data, url) {
    elements.deepScanLoading.style.display = 'none';
    elements.deepScanResults.style.display = 'block';
    
    // Set target URL
    elements.scanTarget.textContent = url;
    
    // Use the grade and score from the API if available
    const grade = data.security_grade || calculateSecurityGrade(data);
    displaySecurityGrade(grade);
    
    // Display security score if available
    if (data.security_score !== undefined) {
        displaySecurityScore(data.security_score);
    }
    
    // Build scan panels - use correct API response keys
    let gridHtml = '';
    
    // Overview Panel (new)
    gridHtml += buildOverviewPanel(data);
    
    // SSL Panel (API uses ssl_analysis)
    if (data.ssl_analysis) {
        gridHtml += buildSSLPanel(data.ssl_analysis);
    } else if (data.ssl) {
        gridHtml += buildSSLPanel(data.ssl);
    }
    
    // Headers Panel (API uses security_headers)
    if (data.security_headers) {
        gridHtml += buildHeadersPanel(data.security_headers);
    } else if (data.headers) {
        gridHtml += buildHeadersPanel(data.headers);
    }
    
    // DNS Panel (API uses dns_records)
    if (data.dns_records) {
        gridHtml += buildDNSPanel(data.dns_records);
    } else if (data.dns) {
        gridHtml += buildDNSPanel(data.dns);
    }
    
    // Technologies Panel (API uses technology)
    if (data.technology) {
        gridHtml += buildTechPanel(data.technology);
    } else if (data.technologies) {
        gridHtml += buildTechPanel(data.technologies);
    }
    
    // Ports Panel (API uses open_ports)
    if (data.open_ports) {
        gridHtml += buildPortsPanel(data.open_ports);
    } else if (data.ports) {
        gridHtml += buildPortsPanel(data.ports);
    }
    
    // Redirects Panel (API uses redirect_chain)
    if (data.redirect_chain) {
        gridHtml += buildRedirectPanel(data.redirect_chain);
    } else if (data.redirects) {
        gridHtml += buildRedirectPanel(data.redirects);
    }
    
    elements.deepScanGrid.innerHTML = gridHtml;
    
    // Display findings
    displayFindings(data);
    
    return grade;
}

/**
 * Display security score
 */
function displaySecurityScore(score) {
    const scoreElement = document.getElementById('securityScoreValue');
    if (scoreElement) {
        scoreElement.textContent = score;
        // Add color based on score
        if (score >= 80) scoreElement.style.color = 'var(--success)';
        else if (score >= 60) scoreElement.style.color = 'var(--warning)';
        else scoreElement.style.color = 'var(--danger)';
    }
}

/**
 * Build overview panel HTML
 */
function buildOverviewPanel(data) {
    const scanTime = data.scan_time ? new Date(data.scan_time).toLocaleString() : '—';
    
    return `
        <div class="scan-panel">
            <div class="scan-panel-header">
                <div class="scan-panel-icon icon-overview">📊</div>
                <div>
                    <div class="scan-panel-title">Scan Overview</div>
                    <div class="scan-panel-subtitle">Summary of deep scan</div>
                </div>
            </div>
            <div class="scan-row">
                <span class="scan-key">Target</span>
                <span class="scan-val">${data.hostname || data.target || '—'}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Security Score</span>
                <span class="scan-val score-value" style="color: ${data.security_score >= 80 ? 'var(--success)' : data.security_score >= 60 ? 'var(--warning)' : 'var(--danger)'}">${data.security_score || '—'}/100</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Security Grade</span>
                <span class="scan-val grade-inline grade-${(data.security_grade || 'f').toLowerCase()}">${data.security_grade || '—'}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Scan Time</span>
                <span class="scan-val">${scanTime}</span>
            </div>
        </div>
    `;
}

/**
 * Calculate security grade
 */
function calculateSecurityGrade(data) {
    let score = 100;
    
    // SSL checks
    if (!data.ssl?.valid) score -= 20;
    if (data.ssl?.expires_soon) score -= 10;
    
    // Header checks
    const securityHeaders = ['Strict-Transport-Security', 'X-Content-Type-Options', 
                            'X-Frame-Options', 'Content-Security-Policy'];
    if (data.headers?.security_headers) {
        securityHeaders.forEach(header => {
            if (!data.headers.security_headers[header]) score -= 5;
        });
    }
    
    // Open ports
    if (data.ports?.open_ports?.length > 5) score -= 15;
    
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
}

/**
 * Display security grade
 */
function displaySecurityGrade(grade) {
    elements.gradeCircle.textContent = grade;
    elements.gradeCircle.className = `grade-circle grade-${grade.toLowerCase()}`;
}

/**
 * Build SSL panel HTML
 */
function buildSSLPanel(ssl) {
    const isEnabled = ssl.enabled !== false;
    const isValid = ssl.valid === true;
    const statusClass = isValid ? 'badge-success' : (isEnabled ? 'badge-warning' : 'badge-danger');
    const statusText = isValid ? 'Valid' : (isEnabled ? 'Enabled (Unverified)' : 'Not Enabled');
    
    // Calculate days until expiry display
    let expiryDisplay = ssl.expires || '—';
    if (ssl.days_until_expiry !== null && ssl.days_until_expiry !== undefined) {
        const days = ssl.days_until_expiry;
        if (days < 0) {
            expiryDisplay += ` <span class="text-danger">(Expired)</span>`;
        } else if (days <= 30) {
            expiryDisplay += ` <span class="text-warning">(${days} days left)</span>`;
        } else {
            expiryDisplay += ` <span class="text-success">(${days} days left)</span>`;
        }
    }
    
    return `
        <div class="scan-panel">
            <div class="scan-panel-header">
                <div class="scan-panel-icon icon-ssl">🔒</div>
                <div>
                    <div class="scan-panel-title">SSL Certificate</div>
                    <div class="scan-panel-subtitle">TLS/SSL security status</div>
                </div>
            </div>
            <div class="scan-row">
                <span class="scan-key">SSL Enabled</span>
                <span class="status-badge ${isEnabled ? 'badge-success' : 'badge-danger'}">${isEnabled ? 'Yes' : 'No'}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Certificate Status</span>
                <span class="status-badge ${statusClass}">${statusText}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Protocol</span>
                <span class="scan-val">${ssl.protocol || '—'}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Cipher Suite</span>
                <span class="scan-val">${ssl.cipher || '—'}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Issuer</span>
                <span class="scan-val">${ssl.issuer || '—'}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Subject</span>
                <span class="scan-val">${ssl.subject || '—'}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Expires</span>
                <span class="scan-val">${expiryDisplay}</span>
            </div>
            ${ssl.error ? `<div class="scan-row"><span class="scan-key">Note</span><span class="scan-val text-muted">${ssl.error}</span></div>` : ''}
        </div>
    `;
}

/**
 * Build headers panel HTML
 */
function buildHeadersPanel(headers) {
    // Handle both old and new API response formats
    const headerData = headers.headers || headers.security_headers || {};
    const presentCount = headers.present_count ?? 0;
    const totalHeaders = headers.total_headers ?? Object.keys(headerData).length;
    const headerScore = headers.score ?? 0;
    
    let checksHtml = '';
    
    // If headers is an object with detailed info
    if (typeof headerData === 'object' && Object.keys(headerData).length > 0) {
        Object.entries(headerData).forEach(([key, info]) => {
            const present = info?.present || info === true;
            const value = info?.value || (typeof info === 'string' ? info : null);
            const recommendation = info?.recommendation;
            
            checksHtml += `
                <div class="header-check-row">
                    <div class="header-check">
                        <span class="header-check-icon ${present ? 'check-pass' : 'check-fail'}">
                            ${present ? '✓' : '✕'}
                        </span>
                        <span class="header-name">${key}</span>
                    </div>
                    ${value ? `<div class="header-value">${value}</div>` : ''}
                    ${!present && recommendation ? `<div class="header-recommendation">${recommendation}</div>` : ''}
                </div>
            `;
        });
    }
    
    // Server and additional info
    let serverInfo = '';
    if (headers.server) {
        serverInfo += `<div class="scan-row"><span class="scan-key">Server</span><span class="scan-val">${headers.server}</span></div>`;
    }
    if (headers.powered_by && headers.powered_by !== 'Not disclosed') {
        serverInfo += `<div class="scan-row"><span class="scan-key">Powered By</span><span class="scan-val">${headers.powered_by}</span></div>`;
    }
    
    return `
        <div class="scan-panel">
            <div class="scan-panel-header">
                <div class="scan-panel-icon icon-headers">📋</div>
                <div>
                    <div class="scan-panel-title">Security Headers</div>
                    <div class="scan-panel-subtitle">HTTP security headers check (${presentCount}/${totalHeaders})</div>
                </div>
            </div>
            <div class="scan-row">
                <span class="scan-key">Header Score</span>
                <span class="scan-val" style="color: ${headerScore >= 60 ? 'var(--success)' : headerScore >= 30 ? 'var(--warning)' : 'var(--danger)'}">${headerScore}%</span>
            </div>
            ${serverInfo}
            <div class="headers-list">
                ${checksHtml}
            </div>
        </div>
    `;
}

/**
 * Build DNS panel HTML
 */
function buildDNSPanel(dns) {
    // Helper to format array or single value
    const formatRecords = (records) => {
        if (!records) return '—';
        if (Array.isArray(records)) {
            if (records.length === 0) return '—';
            return records.join(', ');
        }
        return records;
    };
    
    // Handle both old format (a_record) and new format (a_records array)
    const aRecords = formatRecords(dns.a_records || dns.a_record);
    const aaaaRecords = formatRecords(dns.aaaa_records || dns.aaaa_record);
    const mxRecords = formatRecords(dns.mx_records || dns.mx_record);
    const nsRecords = formatRecords(dns.ns_records || dns.ns_record);
    const txtRecords = formatRecords(dns.txt_records || dns.txt_record);
    const cname = dns.cname || '—';
    
    return `
        <div class="scan-panel">
            <div class="scan-panel-header">
                <div class="scan-panel-icon icon-dns">🔍</div>
                <div>
                    <div class="scan-panel-title">DNS Records</div>
                    <div class="scan-panel-subtitle">Domain name system info</div>
                </div>
            </div>
            <div class="scan-row">
                <span class="scan-key">A Records (IPv4)</span>
                <span class="scan-val">${aRecords}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">AAAA Records (IPv6)</span>
                <span class="scan-val">${aaaaRecords}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">MX Records (Mail)</span>
                <span class="scan-val">${mxRecords}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">NS Records</span>
                <span class="scan-val">${nsRecords}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">CNAME</span>
                <span class="scan-val">${cname}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">TXT Records</span>
                <span class="scan-val">${txtRecords}</span>
            </div>
        </div>
    `;
}

/**
 * Build technologies panel HTML
 */
function buildTechPanel(tech) {
    let techRows = '';
    let techTags = '';
    
    // Handle object format from API
    if (tech && typeof tech === 'object' && !Array.isArray(tech)) {
        // Server
        if (tech.server) {
            techRows += `<div class="scan-row"><span class="scan-key">Server</span><span class="scan-val">${tech.server}</span></div>`;
        }
        
        // CMS
        if (tech.cms) {
            techRows += `<div class="scan-row"><span class="scan-key">CMS</span><span class="scan-val">${tech.cms}</span></div>`;
        }
        
        // Framework
        if (tech.framework) {
            techRows += `<div class="scan-row"><span class="scan-key">Framework</span><span class="scan-val">${tech.framework}</span></div>`;
        }
        
        // CDN
        if (tech.cdn) {
            techRows += `<div class="scan-row"><span class="scan-key">CDN</span><span class="scan-val">${tech.cdn}</span></div>`;
        }
        
        // JavaScript Libraries
        if (tech.javascript_libraries && tech.javascript_libraries.length > 0) {
            techRows += `<div class="scan-row"><span class="scan-key">JS Libraries</span><span class="scan-val">${tech.javascript_libraries.join(', ')}</span></div>`;
        }
        
        // Analytics
        if (tech.analytics && tech.analytics.length > 0) {
            techRows += `<div class="scan-row"><span class="scan-key">Analytics</span><span class="scan-val">${tech.analytics.join(', ')}</span></div>`;
        }
        
        // Detected technologies as tags
        if (tech.detected && Array.isArray(tech.detected) && tech.detected.length > 0) {
            tech.detected.forEach(t => {
                techTags += `<span class="tech-tag">${t}</span>`;
            });
        }
    } else if (Array.isArray(tech) && tech.length > 0) {
        // Handle array format
        tech.forEach(t => {
            techTags += `<span class="tech-tag">${t}</span>`;
        });
    }
    
    // If nothing detected
    if (!techRows && !techTags) {
        techTags = '<span class="scan-val">No technologies detected</span>';
    }
    
    return `
        <div class="scan-panel">
            <div class="scan-panel-header">
                <div class="scan-panel-icon icon-tech">⚙️</div>
                <div>
                    <div class="scan-panel-title">Technologies</div>
                    <div class="scan-panel-subtitle">Detected frameworks & tools</div>
                </div>
            </div>
            ${techRows}
            ${techTags ? `<div class="tech-tags-container">${techTags}</div>` : ''}
        </div>
    `;
}

/**
 * Build ports panel HTML
 */
function buildPortsPanel(ports) {
    let openPortsHtml = '';
    let closedPortsHtml = '';
    
    // Handle new API format with detailed port objects
    const openPortsList = ports.open_ports || [];
    const closedPortsList = ports.closed_ports || [];
    const scannedCount = ports.scanned || (openPortsList.length + closedPortsList.length);
    
    // Safe ports (standard web ports)
    const safePorts = [80, 443];
    
    // Build open ports display
    if (openPortsList.length > 0) {
        openPortsList.forEach(portInfo => {
            // Handle both object format and simple number format
            const port = typeof portInfo === 'object' ? portInfo.port : portInfo;
            const service = typeof portInfo === 'object' ? portInfo.service : null;
            const isSafe = safePorts.includes(port);
            const isRisky = [21, 22, 23, 25, 3306, 3389, 5432].includes(port);
            
            let portClass = isSafe ? 'port-safe' : (isRisky ? 'port-risky' : 'port-open');
            
            openPortsHtml += `
                <div class="port-item ${portClass}">
                    <span class="port-number">${port}</span>
                    ${service ? `<span class="port-service">${service}</span>` : ''}
                </div>
            `;
        });
    } else {
        openPortsHtml = '<span class="scan-val">No open ports found</span>';
    }
    
    // Build closed ports summary (collapsed)
    let closedSummary = '';
    if (closedPortsList.length > 0) {
        const closedServices = closedPortsList.map(p => 
            typeof p === 'object' ? `${p.port} (${p.service})` : p
        ).slice(0, 5).join(', ');
        const moreCount = closedPortsList.length > 5 ? ` +${closedPortsList.length - 5} more` : '';
        closedSummary = `<div class="scan-row"><span class="scan-key">Closed</span><span class="scan-val text-muted">${closedServices}${moreCount}</span></div>`;
    }
    
    return `
        <div class="scan-panel">
            <div class="scan-panel-header">
                <div class="scan-panel-icon icon-ports">🔌</div>
                <div>
                    <div class="scan-panel-title">Port Scan</div>
                    <div class="scan-panel-subtitle">Scanned ${scannedCount} common ports</div>
                </div>
            </div>
            <div class="scan-row">
                <span class="scan-key">Open Ports</span>
                <span class="scan-val">${openPortsList.length}</span>
            </div>
            <div class="scan-row">
                <span class="scan-key">Closed Ports</span>
                <span class="scan-val">${closedPortsList.length}</span>
            </div>
            <div class="ports-container">
                ${openPortsHtml}
            </div>
            ${closedSummary}
        </div>
    `;
}

/**
 * Build redirect panel HTML
 */
function buildRedirectPanel(redirects) {
    let redirectHtml = '';
    
    // Handle new API format with detailed redirect info
    const hasRedirects = redirects.has_redirects || false;
    const redirectChain = redirects.chain || [];
    const finalUrl = redirects.final_url || null;
    const redirectCount = redirects.count || redirectChain.length;
    const httpsUpgrade = redirects.https_upgrade || false;
    
    if (hasRedirects && redirectChain.length > 0) {
        redirectChain.forEach((redirect, index) => {
            // Handle object format with detailed info
            if (typeof redirect === 'object') {
                const statusClass = redirect.status_code >= 300 && redirect.status_code < 400 ? 'redirect-status' : '';
                redirectHtml += `
                    <div class="redirect-step">
                        <div class="redirect-step-num">${index + 1}</div>
                        <div class="redirect-step-info">
                            <div class="redirect-url">${redirect.url}</div>
                            <div class="redirect-meta">
                                <span class="status-code ${statusClass}">${redirect.status_code}</span>
                                <span class="redirect-arrow">→</span>
                                <span class="redirect-target">${redirect.redirects_to}</span>
                            </div>
                        </div>
                    </div>
                `;
            } else {
                // Simple string format
                redirectHtml += `
                    <div class="scan-row">
                        <span class="scan-key">Step ${index + 1}</span>
                        <span class="scan-val">${redirect}</span>
                    </div>
                `;
            }
        });
        
        // Show final destination
        if (finalUrl) {
            redirectHtml += `
                <div class="redirect-final">
                    <span class="scan-key">✔ Final URL</span>
                    <span class="scan-val">${finalUrl}</span>
                </div>
            `;
        }
    } else if (Array.isArray(redirects) && redirects.length > 0) {
        // Handle old array format
        redirects.forEach((redirect, index) => {
            redirectHtml += `
                <div class="scan-row">
                    <span class="scan-key">Step ${index + 1}</span>
                    <span class="scan-val">${redirect}</span>
                </div>
            `;
        });
    } else {
        redirectHtml = '<div class="scan-row"><span class="scan-val text-success">✔ No redirects - Direct access</span></div>';
    }
    
    return `
        <div class="scan-panel">
            <div class="scan-panel-header">
                <div class="scan-panel-icon icon-redirect">↪️</div>
                <div>
                    <div class="scan-panel-title">Redirect Chain</div>
                    <div class="scan-panel-subtitle">${redirectCount} redirect${redirectCount !== 1 ? 's' : ''} detected</div>
                </div>
            </div>
            ${httpsUpgrade ? '<div class="scan-row"><span class="scan-key">HTTPS Upgrade</span><span class="status-badge badge-success">Yes</span></div>' : ''}
            <div class="redirects-container">
                ${redirectHtml}
            </div>
        </div>
    `;
}

/**
 * Display security findings
 */
function displayFindings(data) {
    let findings = [];
    
    // Use findings from API if available
    if (data.findings && Array.isArray(data.findings) && data.findings.length > 0) {
        findings = data.findings.map(f => ({
            type: f.type === 'success' ? 'success' : 
                  f.type === 'warning' ? 'warning' : 
                  f.type === 'danger' || f.type === 'error' ? 'danger' : 'info',
            icon: f.type === 'success' ? '✓' : 
                  f.type === 'warning' ? '⚠' : 
                  f.type === 'danger' || f.type === 'error' ? '✕' : 'ℹ',
            text: f.message || f.text || JSON.stringify(f)
        }));
    } else {
        // Fallback to building findings manually
        
        // SSL findings
        const ssl = data.ssl_analysis || data.ssl;
        if (ssl) {
            if (ssl.enabled) {
                findings.push({ type: 'success', icon: '✓', text: 'HTTPS/SSL is enabled' });
            }
            if (ssl.valid) {
                findings.push({ type: 'success', icon: '✓', text: 'SSL certificate is valid and properly configured' });
            } else if (ssl.enabled) {
                findings.push({ type: 'warning', icon: '⚠', text: 'SSL certificate validation issue' });
            }
            if (ssl.protocol) {
                findings.push({ type: 'info', icon: 'ℹ', text: `Using ${ssl.protocol} protocol` });
            }
        }
        
        // Header findings
        const headers = data.security_headers || data.headers;
        if (headers) {
            const headerData = headers.headers || {};
            const presentCount = headers.present_count || 0;
            const totalHeaders = headers.total_headers || 8;
            
            if (presentCount > 0) {
                findings.push({ 
                    type: presentCount >= totalHeaders / 2 ? 'success' : 'warning', 
                    icon: presentCount >= totalHeaders / 2 ? '✓' : '⚠', 
                    text: `Security headers: ${presentCount}/${totalHeaders} present` 
                });
            }
            
            // Check specific important headers
            if (headerData['Strict-Transport-Security']?.present) {
                findings.push({ type: 'success', icon: '✓', text: 'HSTS header is enabled' });
            } else {
                findings.push({ type: 'warning', icon: '⚠', text: 'HSTS header is missing - recommended for security' });
            }
            
            if (!headerData['Content-Security-Policy']?.present) {
                findings.push({ type: 'warning', icon: '⚠', text: 'Content Security Policy header is missing' });
            }
            
            if (headers.server) {
                findings.push({ type: 'info', icon: 'ℹ', text: `Server: ${headers.server}` });
            }
        }
        
        // Port findings
        const ports = data.open_ports || data.ports;
        if (ports?.open_ports) {
            const openPorts = ports.open_ports;
            const riskyPorts = openPorts.filter(p => {
                const port = typeof p === 'object' ? p.port : p;
                return ![80, 443].includes(port) && [21, 22, 23, 25, 3306, 3389, 5432].includes(port);
            });
            
            if (riskyPorts.length > 0) {
                riskyPorts.forEach(p => {
                    const port = typeof p === 'object' ? p.port : p;
                    const service = typeof p === 'object' ? p.service : '';
                    findings.push({ 
                        type: 'warning', 
                        icon: '⚠', 
                        text: `Port ${port}${service ? ` (${service})` : ''} is open` 
                    });
                });
            }
        }
        
        // Redirect findings
        const redirects = data.redirect_chain || data.redirects;
        if (redirects) {
            if (redirects.https_upgrade) {
                findings.push({ type: 'success', icon: '✓', text: 'HTTP to HTTPS upgrade detected' });
            }
            if (!redirects.has_redirects) {
                findings.push({ type: 'success', icon: '✓', text: 'Using HTTPS directly (no redirects)' });
            }
        }
        
        // Technology findings
        const tech = data.technology;
        if (tech?.detected && tech.detected.length > 0) {
            findings.push({ type: 'info', icon: 'ℹ', text: `${tech.detected.length} technologies detected` });
        }
    }
    
    // Count threats
    const threatCount = findings.filter(f => f.type === 'danger' || f.type === 'warning').length;
    if (threatCount > 0) {
        incrementThreats(threatCount);
    }
    
    // Render findings
    let html = '';
    findings.forEach(finding => {
        html += `
            <div class="finding-item finding-${finding.type}">
                <span class="finding-icon">${finding.icon}</span>
                <span>${finding.text}</span>
            </div>
        `;
    });
    
    if (!html) {
        html = '<div class="finding-item finding-info"><span class="finding-icon">ℹ</span><span>No specific findings to report</span></div>';
    }
    
    elements.findingsList.innerHTML = html;
}

// ==================== Keyboard Shortcuts ====================

/**
 * Initialize keyboard shortcuts
 */
function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Don't trigger when typing in inputs
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
            return;
        }
        
        // Ctrl/Cmd + K - Focus URL input
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            elements.urlInput.focus();
        }
        
        // Escape - Clear inputs
        if (e.key === 'Escape') {
            if (document.activeElement === elements.urlInput) {
                clearUrlAnalysis();
            } else if (document.activeElement === elements.deepScanInput) {
                clearDeepScan();
            }
        }
        
        // Number keys for navigation
        if (e.key >= '1' && e.key <= '4') {
            const views = ['networkAnalysisView', 'dashboardView', 'historyView', 'settingsView'];
            const index = parseInt(e.key) - 1;
            if (views[index]) {
                const navItem = document.querySelector(`[data-view="${views[index]}"]`);
                switchView(views[index], navItem);
            }
        }
    });
}

// ==================== History Management ====================

const HISTORY_KEY = 'subveil_history';
const SETTINGS_KEY = 'subveil_settings';

/**
 * Load scan history from localStorage
 */
function loadHistory() {
    try {
        const saved = localStorage.getItem(HISTORY_KEY);
        return saved ? JSON.parse(saved) : [];
    } catch {
        return [];
    }
}

/**
 * Save scan to history
 */
function saveToHistory(url, score, type = 'quick') {
    const settings = loadSettings();
    if (!settings.saveHistory) return;
    
    const history = loadHistory();
    const entry = {
        id: Date.now(),
        url,
        score,
        type,
        status: score >= 70 ? 'safe' : score >= 40 ? 'warning' : 'threat',
        timestamp: new Date().toISOString()
    };
    
    history.unshift(entry);
    
    // Keep only last 100 entries
    if (history.length > 100) {
        history.pop();
    }
    
    try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch (e) {
        console.error('Error saving history:', e);
    }
    
    // Update displays
    updateRecentActivity();
    renderHistoryList();
    updateDashboardStats();
}

/**
 * Render history list
 */
function renderHistoryList(filter = 'all', searchQuery = '') {
    const historyList = document.getElementById('historyList');
    if (!historyList) return;
    
    let history = loadHistory();
    
    // Apply filter
    if (filter !== 'all') {
        history = history.filter(item => item.status === filter);
    }
    
    // Apply search
    if (searchQuery) {
        const query = searchQuery.toLowerCase();
        history = history.filter(item => item.url.toLowerCase().includes(query));
    }
    
    if (history.length === 0) {
        historyList.innerHTML = `
            <div class="history-empty">
                <div class="placeholder-icon">📭</div>
                <h3 class="placeholder-title">${filter !== 'all' || searchQuery ? 'No Matching Results' : 'No Scan History'}</h3>
                <p class="placeholder-text">${filter !== 'all' || searchQuery ? 'Try adjusting your filters or search query.' : 'Your scanned URLs will appear here. Start by analyzing a URL!'}</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    history.forEach(item => {
        const scoreColor = item.score >= 70 ? 'var(--success)' : item.score >= 40 ? 'var(--warning)' : 'var(--danger)';
        const icon = item.score >= 70 ? '✓' : item.score >= 40 ? '⚠' : '✕';
        const date = new Date(item.timestamp);
        const timeAgo = getTimeAgo(date);
        
        html += `
            <div class="history-item" data-id="${item.id}">
                <div class="history-item-icon ${item.status}">${icon}</div>
                <div class="history-item-content">
                    <div class="history-item-url">${item.url}</div>
                    <div class="history-item-meta">
                        <span>📅 ${timeAgo}</span>
                        <span>🔍 ${item.type === 'deep' ? 'Deep Scan' : 'Quick Scan'}</span>
                    </div>
                </div>
                <div class="history-item-score">
                    <div class="history-score-value" style="color: ${scoreColor}">${item.score}</div>
                    <div class="history-score-label">Score</div>
                </div>
                <div class="history-item-actions">
                    <button class="history-action-btn" onclick="rescanUrl('${item.url}')" title="Rescan">🔄</button>
                    <button class="history-action-btn" onclick="copyToClipboard('${item.url}')" title="Copy URL">📋</button>
                    <button class="history-action-btn" onclick="deleteHistoryItem(${item.id})" title="Delete">🗑️</button>
                </div>
            </div>
        `;
    });
    
    historyList.innerHTML = html;
}

/**
 * Get time ago string
 */
function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
    
    return date.toLocaleDateString();
}

/**
 * Delete history item
 */
function deleteHistoryItem(id) {
    let history = loadHistory();
    history = history.filter(item => item.id !== id);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    renderHistoryList();
    updateDashboardStats();
    showToast('success', 'Deleted', 'History item removed');
}

/**
 * Rescan URL
 */
function rescanUrl(url) {
    elements.urlInput.value = url;
    const navItem = document.querySelector('[data-view="networkAnalysisView"]');
    switchView('networkAnalysisView', navItem);
    handleUrlAnalysis();
}

/**
 * Copy to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('success', 'Copied', 'URL copied to clipboard');
    } catch {
        showToast('error', 'Failed', 'Could not copy to clipboard');
    }
}

/**
 * Clear all history
 */
function clearAllHistory() {
    if (confirm('Are you sure you want to clear all scan history?')) {
        localStorage.removeItem(HISTORY_KEY);
        renderHistoryList();
        updateRecentActivity();
        updateDashboardStats();
        showToast('success', 'Cleared', 'All history has been removed');
    }
}

/**
 * Export history as JSON
 */
function exportHistory() {
    const history = loadHistory();
    if (history.length === 0) {
        showToast('warning', 'No Data', 'No history to export');
        return;
    }
    
    const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `subveil-history-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('success', 'Exported', 'History downloaded as JSON');
}

/**
 * Initialize history view
 */
function initHistoryView() {
    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderHistoryList(btn.dataset.filter, document.getElementById('historySearchInput')?.value || '');
        });
    });
    
    // Search input
    const searchInput = document.getElementById('historySearchInput');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(() => {
            const activeFilter = document.querySelector('.filter-btn.active')?.dataset.filter || 'all';
            renderHistoryList(activeFilter, searchInput.value);
        }, 300));
    }
    
    // Clear history button
    document.getElementById('clearHistoryBtn')?.addEventListener('click', clearAllHistory);
    
    // Export button
    document.getElementById('exportHistoryBtn')?.addEventListener('click', exportHistory);
    
    // Initial render
    renderHistoryList();
}

// ==================== Dashboard ====================

/**
 * Update dashboard stats
 */
function updateDashboardStats() {
    const history = loadHistory();
    
    const total = history.length;
    const safe = history.filter(h => h.status === 'safe').length;
    const warnings = history.filter(h => h.status === 'warning').length;
    const threats = history.filter(h => h.status === 'threat').length;
    
    // Update stat cards
    const dashScansTotal = document.getElementById('dashScansTotal');
    const dashSafeUrls = document.getElementById('dashSafeUrls');
    const dashWarnings = document.getElementById('dashWarnings');
    const dashThreats = document.getElementById('dashThreats');
    
    if (dashScansTotal) dashScansTotal.textContent = total;
    if (dashSafeUrls) dashSafeUrls.textContent = safe;
    if (dashWarnings) dashWarnings.textContent = warnings;
    if (dashThreats) dashThreats.textContent = threats;
    
    // Update percentages
    if (total > 0) {
        const safePercent = Math.round((safe / total) * 100);
        const warningPercent = Math.round((warnings / total) * 100);
        const dangerPercent = Math.round((threats / total) * 100);
        
        document.getElementById('safePercentBar')?.style.setProperty('width', `${safePercent}%`);
        document.getElementById('warningPercentBar')?.style.setProperty('width', `${warningPercent}%`);
        document.getElementById('dangerPercentBar')?.style.setProperty('width', `${dangerPercent}%`);
        
        const safePercentEl = document.getElementById('safePercent');
        const warningPercentEl = document.getElementById('warningPercent');
        const dangerPercentEl = document.getElementById('dangerPercent');
        
        if (safePercentEl) safePercentEl.textContent = `${safePercent}%`;
        if (warningPercentEl) warningPercentEl.textContent = `${warningPercent}%`;
        if (dangerPercentEl) dangerPercentEl.textContent = `${dangerPercent}%`;
    }
}

/**
 * Update recent activity
 */
function updateRecentActivity() {
    const activityList = document.getElementById('recentActivityList');
    if (!activityList) return;
    
    const history = loadHistory().slice(0, 5);
    
    if (history.length === 0) {
        activityList.innerHTML = `
            <div class="activity-empty">
                <span>📭</span>
                <p>No recent activity. Start scanning URLs!</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    history.forEach(item => {
        const icon = item.score >= 70 ? '✓' : item.score >= 40 ? '⚠' : '✕';
        const scoreColor = item.score >= 70 ? 'var(--success)' : item.score >= 40 ? 'var(--warning)' : 'var(--danger)';
        const timeAgo = getTimeAgo(new Date(item.timestamp));
        
        html += `
            <div class="activity-item">
                <div class="activity-icon ${item.status}">${icon}</div>
                <div class="activity-content">
                    <div class="activity-url">${formatUrl(item.url)}</div>
                    <div class="activity-time">${timeAgo}</div>
                </div>
                <div class="activity-score" style="color: ${scoreColor}">${item.score}</div>
            </div>
        `;
    });
    
    activityList.innerHTML = html;
}

/**
 * Initialize dashboard
 */
function initDashboard() {
    updateDashboardStats();
    updateRecentActivity();
    
    // Quick actions
    document.querySelectorAll('.quick-action-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const action = btn.dataset.action;
            switch (action) {
                case 'newScan':
                    switchView('networkAnalysisView', document.querySelector('[data-view="networkAnalysisView"]'));
                    elements.urlInput.focus();
                    break;
                case 'deepScan':
                    switchView('networkAnalysisView', document.querySelector('[data-view="networkAnalysisView"]'));
                    elements.deepScanInput.focus();
                    break;
                case 'viewHistory':
                    switchView('historyView', document.querySelector('[data-view="historyView"]'));
                    break;
                case 'exportData':
                    exportHistory();
                    break;
            }
        });
    });
}

// ==================== Settings ====================

/**
 * Load settings
 */
function loadSettings() {
    try {
        const saved = localStorage.getItem(SETTINGS_KEY);
        return saved ? JSON.parse(saved) : {
            showToasts: true,
            playSounds: false,
            saveHistory: true,
            apiUrl: 'http://localhost:8000/api',
            timeout: 30000
        };
    } catch {
        return {
            showToasts: true,
            playSounds: false,
            saveHistory: true,
            apiUrl: 'http://localhost:8000/api',
            timeout: 30000
        };
    }
}

/**
 * Save settings
 */
function saveSettings(settings) {
    try {
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
        // Update config
        if (settings.apiUrl) CONFIG.API_BASE = settings.apiUrl;
    } catch (e) {
        console.error('Error saving settings:', e);
    }
}

/**
 * Initialize settings
 */
function initSettings() {
    const settings = loadSettings();
    
    // Apply saved settings to UI
    const toastsToggle = document.getElementById('settingToasts');
    const soundsToggle = document.getElementById('settingSounds');
    const historyToggle = document.getElementById('settingHistory');
    const apiUrlInput = document.getElementById('settingApiUrl');
    const timeoutSelect = document.getElementById('settingTimeout');
    
    if (toastsToggle) toastsToggle.checked = settings.showToasts;
    if (soundsToggle) soundsToggle.checked = settings.playSounds;
    if (historyToggle) historyToggle.checked = settings.saveHistory;
    if (apiUrlInput) apiUrlInput.value = settings.apiUrl || CONFIG.API_BASE;
    if (timeoutSelect) timeoutSelect.value = settings.timeout || 30000;
    
    // Add event listeners
    [toastsToggle, soundsToggle, historyToggle].forEach(toggle => {
        toggle?.addEventListener('change', () => {
            const newSettings = {
                showToasts: toastsToggle?.checked ?? true,
                playSounds: soundsToggle?.checked ?? false,
                saveHistory: historyToggle?.checked ?? true,
                apiUrl: apiUrlInput?.value || CONFIG.API_BASE,
                timeout: parseInt(timeoutSelect?.value) || 30000
            };
            saveSettings(newSettings);
            showToast('success', 'Settings Saved', 'Your preferences have been updated');
        });
    });
    
    apiUrlInput?.addEventListener('change', () => {
        const newSettings = loadSettings();
        newSettings.apiUrl = apiUrlInput.value;
        saveSettings(newSettings);
        showToast('success', 'API URL Updated', 'Backend URL has been changed');
    });
    
    timeoutSelect?.addEventListener('change', () => {
        const newSettings = loadSettings();
        newSettings.timeout = parseInt(timeoutSelect.value);
        saveSettings(newSettings);
        showToast('success', 'Timeout Updated', 'Request timeout has been changed');
    });
    
    // Clear all data
    document.getElementById('clearAllDataBtn')?.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all data? This cannot be undone.')) {
            localStorage.removeItem(HISTORY_KEY);
            localStorage.removeItem(CONFIG.STORAGE_KEY);
            state.stats = { scansToday: 0, threatsFound: 0, urlsAnalyzed: 0 };
            updateStatsDisplay();
            updateDashboardStats();
            updateRecentActivity();
            renderHistoryList();
            showToast('success', 'Data Cleared', 'All data has been removed');
        }
    });
    
    // Export all data
    document.getElementById('exportAllDataBtn')?.addEventListener('click', () => {
        const data = {
            history: loadHistory(),
            stats: state.stats,
            settings: loadSettings(),
            exportDate: new Date().toISOString()
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `subveil-export-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('success', 'Data Exported', 'All data downloaded as JSON');
    });
}

// ==================== Initialization ====================

/**
 * Initialize the application
 */
function init() {
    loadStats();
    initNavigation();
    initMobileMenu();
    initUrlAnalysis();
    initDeepScan();
    initKeyboardShortcuts();
    initHistoryView();
    initDashboard();
    initSettings();
    
    // Apply saved API URL
    const settings = loadSettings();
    if (settings.apiUrl) {
        CONFIG.API_BASE = settings.apiUrl;
    }
    
    // Initial toast
    if (settings.showToasts !== false) {
        showToast('info', 'Welcome to SubVeil', 'Cyber Intelligence Dashboard ready');
    }
    
    console.log('🛡️ SubVeil initialized successfully');
}

// Start the application when DOM is ready
document.addEventListener('DOMContentLoaded', init);
