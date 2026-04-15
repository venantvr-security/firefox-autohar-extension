// AutoHAR Panel - Capture et analyse de securite du trafic reseau
// Pentest Edition

class AutoHARCapture {
  constructor() {
    this.isRecording = false;
    this.requests = [];
    this.totalSize = 0;
    this.savedFilesCount = 0;
    this.savedFiles = [];
    this.settings = {
      maxSizeMB: 5,
      autoSave: true,
      includeResponses: true,
      domainFilter: '',
      ignoreStatic: true,
      apiOnlyMode: false,
      excludeThirdParty: false,
      deduplicate: true
    };

    // Security Analyzer
    this.securityAnalyzer = new SecurityAnalyzer({
      filters: {
        ignoreStatic: this.settings.ignoreStatic,
        apiOnlyMode: this.settings.apiOnlyMode,
        excludeThirdParty: this.settings.excludeThirdParty
      },
      deduplicate: this.settings.deduplicate
    });

    // Callbacks pour updates UI
    this.securityAnalyzer.onUpdate = (summary) => this.updateSecurityUI(summary);

    // Current export data
    this.currentExport = { content: '', filename: '', mimeType: 'text/plain' };

    this.initUI();
    this.loadSettings();
    this.bindEvents();
  }

  initUI() {
    this.elements = {
      // Header
      statusIndicator: document.getElementById('statusIndicator'),
      btnToggle: document.getElementById('btnToggle'),
      btnSaveNow: document.getElementById('btnSaveNow'),
      btnClear: document.getElementById('btnClear'),

      // Capture stats
      requestCount: document.getElementById('requestCount'),
      currentSize: document.getElementById('currentSize'),
      savedCount: document.getElementById('savedCount'),
      progressFill: document.getElementById('progressFill'),
      progressText: document.getElementById('progressText'),

      // Settings
      autoSave: document.getElementById('autoSave'),
      maxSize: document.getElementById('maxSize'),
      includeResponses: document.getElementById('includeResponses'),
      domainFilter: document.getElementById('domainFilter'),
      filterStatic: document.getElementById('filterStatic'),
      filterApiOnly: document.getElementById('filterApiOnly'),
      filterThirdParty: document.getElementById('filterThirdParty'),
      filterDedupe: document.getElementById('filterDedupe'),

      // Log
      logContainer: document.getElementById('logContainer'),
      savedFiles: document.getElementById('savedFiles'),

      // Tabs
      tabButtons: document.querySelectorAll('.tab-btn'),
      tabContents: document.querySelectorAll('.tab-content'),

      // Security tab
      securityBadge: document.getElementById('securityBadge'),
      criticalCount: document.getElementById('criticalCount'),
      highCount: document.getElementById('highCount'),
      mediumCount: document.getElementById('mediumCount'),
      secretsCount: document.getElementById('secretsCount'),
      findingsList: document.getElementById('findingsList'),

      // Endpoints tab
      endpointsBadge: document.getElementById('endpointsBadge'),
      endpointSearch: document.getElementById('endpointSearch'),
      methodFilter: document.getElementById('methodFilter'),
      showIdorOnly: document.getElementById('showIdorOnly'),
      endpointsTotal: document.getElementById('endpointsTotal'),
      paramsTotal: document.getElementById('paramsTotal'),
      idorTotal: document.getElementById('idorTotal'),
      jsEndpointsTotal: document.getElementById('jsEndpointsTotal'),
      endpointsList: document.getElementById('endpointsList'),

      // Export tab
      exportFfuf: document.getElementById('exportFfuf'),
      exportPostman: document.getElementById('exportPostman'),
      exportCurl: document.getElementById('exportCurl'),
      exportParams: document.getElementById('exportParams'),
      exportMarkdown: document.getElementById('exportMarkdown'),
      exportJSON: document.getElementById('exportJSON'),
      exportNuclei: document.getElementById('exportNuclei'),
      exportOutput: document.getElementById('exportOutput'),
      copyExport: document.getElementById('copyExport'),
      downloadExport: document.getElementById('downloadExport'),

      // AI Export tab
      aiExportBrief: document.getElementById('aiExportBrief'),
      aiExportScenarios: document.getElementById('aiExportScenarios'),
      aiExportOpenAPI: document.getElementById('aiExportOpenAPI'),
      aiExportChunked: document.getElementById('aiExportChunked'),
      categoryPills: document.getElementById('categoryPills'),
      promptList: document.getElementById('promptList'),
      aiPromptOutput: document.getElementById('aiPromptOutput'),
      tokenCount: document.getElementById('tokenCount'),
      aiCopyPrompt: document.getElementById('aiCopyPrompt'),
      aiDownloadPrompt: document.getElementById('aiDownloadPrompt'),
      aiEditPrompt: document.getElementById('aiEditPrompt'),
      aiAddPrompt: document.getElementById('aiAddPrompt'),
      promptModal: document.getElementById('promptModal'),
      promptModalTitle: document.getElementById('promptModalTitle'),
      promptName: document.getElementById('promptName'),
      promptCategory: document.getElementById('promptCategory'),
      promptDescription: document.getElementById('promptDescription'),
      promptContent: document.getElementById('promptContent'),
      promptModalCancel: document.getElementById('promptModalCancel'),
      promptModalSave: document.getElementById('promptModalSave')
    };

    // AI Export manager
    this.aiExportManager = new AIExportManager(this.securityAnalyzer);
    this.openAPIGenerator = new OpenAPIGenerator();
    this.selectedPromptId = null;
    this.editingPromptId = null;
  }

  async loadSettings() {
    let shouldAutoStart = false;

    try {
      const response = await browser.runtime.sendMessage({ action: 'getSettings' });
      if (response) {
        this.settings.maxSizeMB = response.maxSizeMB || 5;
        this.elements.maxSize.value = this.settings.maxSizeMB;
        this.elements.autoSave.checked = response.autoStartOnDevTools !== false;
        shouldAutoStart = response.autoStartOnDevTools === true;
      }
    } catch (e) {
      console.error('Erreur chargement parametres:', e);
      this.log('Parametres par defaut charges', 'info');
    }

    const storage = await browser.storage.local.get('recordingCommand');
    if (storage.recordingCommand === 'start') {
      shouldAutoStart = true;
      browser.storage.local.remove('recordingCommand');
    } else if (storage.recordingCommand === 'stop') {
      shouldAutoStart = false;
      this.stopRecording();
      browser.storage.local.remove('recordingCommand');
    }

    if (shouldAutoStart && !this.isRecording) {
      this.startRecording();
    }

    this.syncStateToStorage();
    this.notifyPanelReady();
  }

  notifyPanelReady() {
    browser.runtime.sendMessage({ action: 'panelReady' }).catch(() => {});
  }

  bindEvents() {
    // Main controls
    this.elements.btnToggle.addEventListener('click', () => this.toggleRecording());
    this.elements.btnSaveNow.addEventListener('click', () => this.saveHAR());
    this.elements.btnClear.addEventListener('click', () => this.clearCapture());

    // Settings
    this.elements.maxSize.addEventListener('change', (e) => {
      this.settings.maxSizeMB = parseInt(e.target.value) || 5;
      this.saveSettings();
      this.updateProgress();
    });

    this.elements.autoSave.addEventListener('change', (e) => {
      this.settings.autoSave = e.target.checked;
      this.saveSettings();
    });

    this.elements.includeResponses.addEventListener('change', (e) => {
      this.settings.includeResponses = e.target.checked;
    });

    this.elements.domainFilter.addEventListener('input', (e) => {
      this.settings.domainFilter = e.target.value.toLowerCase().trim();
    });

    // Smart filters
    this.elements.filterStatic.addEventListener('change', (e) => {
      this.settings.ignoreStatic = e.target.checked;
      this.securityAnalyzer.updateFilters({ ignoreStatic: e.target.checked });
    });

    this.elements.filterApiOnly.addEventListener('change', (e) => {
      this.settings.apiOnlyMode = e.target.checked;
      this.securityAnalyzer.updateFilters({ apiOnlyMode: e.target.checked });
    });

    this.elements.filterThirdParty.addEventListener('change', (e) => {
      this.settings.excludeThirdParty = e.target.checked;
      this.securityAnalyzer.updateFilters({ excludeThirdParty: e.target.checked });
    });

    this.elements.filterDedupe.addEventListener('change', (e) => {
      this.settings.deduplicate = e.target.checked;
      this.securityAnalyzer.setOptions({ deduplicate: e.target.checked });
    });

    // Tab navigation
    this.elements.tabButtons.forEach(btn => {
      btn.addEventListener('click', () => this.switchTab(btn.dataset.tab));
    });

    // Endpoint filters
    this.elements.endpointSearch.addEventListener('input', () => this.renderEndpoints());
    this.elements.methodFilter.addEventListener('change', () => this.renderEndpoints());
    this.elements.showIdorOnly.addEventListener('change', () => this.renderEndpoints());

    // Export buttons
    this.elements.exportFfuf.addEventListener('click', () => this.doExport('ffuf'));
    this.elements.exportPostman.addEventListener('click', () => this.doExport('postman'));
    this.elements.exportCurl.addEventListener('click', () => this.doExport('curl'));
    this.elements.exportParams.addEventListener('click', () => this.doExport('params'));
    this.elements.exportMarkdown.addEventListener('click', () => this.doExport('markdown'));
    this.elements.exportJSON.addEventListener('click', () => this.doExport('json'));
    this.elements.exportNuclei.addEventListener('click', () => this.doExport('nuclei'));
    this.elements.copyExport.addEventListener('click', () => this.copyExportToClipboard());
    this.elements.downloadExport.addEventListener('click', () => this.downloadExport());

    // AI Export buttons
    this.elements.aiExportBrief.addEventListener('click', () => this.aiDoExport('brief'));
    this.elements.aiExportScenarios.addEventListener('click', () => this.aiDoExport('scenarios'));
    this.elements.aiExportOpenAPI.addEventListener('click', () => this.aiDoExport('openapi'));
    this.elements.aiExportChunked.addEventListener('click', () => this.aiDoExport('chunked'));

    // Category pills
    this.elements.categoryPills.addEventListener('click', (e) => {
      if (e.target.classList.contains('category-pill')) {
        this.elements.categoryPills.querySelectorAll('.category-pill').forEach(p => p.classList.remove('active'));
        e.target.classList.add('active');
        this.renderPromptList(e.target.dataset.category);
      }
    });

    // AI prompt actions
    this.elements.aiCopyPrompt.addEventListener('click', () => this.aiCopyPrompt());
    this.elements.aiDownloadPrompt.addEventListener('click', () => this.aiDownloadPrompt());
    this.elements.aiEditPrompt.addEventListener('click', () => this.aiEditCurrentPrompt());
    this.elements.aiAddPrompt.addEventListener('click', () => this.aiShowPromptModal());

    // Prompt modal
    this.elements.promptModalCancel.addEventListener('click', () => this.aiHidePromptModal());
    this.elements.promptModalSave.addEventListener('click', () => this.aiSavePrompt());

    // Close modal on overlay click
    this.elements.promptModal.addEventListener('click', (e) => {
      if (e.target === this.elements.promptModal) {
        this.aiHidePromptModal();
      }
    });

    // Network listener
    if (browser.devtools.network.onRequestFinished) {
      browser.devtools.network.onRequestFinished.addListener((request) => {
        this.handleRequest(request);
      });
    }

    // Message listener
    browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === 'startRecordingCommand') {
        this.startRecording();
        sendResponse({ success: true });
        return true;
      } else if (message.action === 'stopRecordingCommand') {
        this.stopRecording();
        sendResponse({ success: true });
        return true;
      }
    });
  }

  switchTab(tabName) {
    this.elements.tabButtons.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    this.elements.tabContents.forEach(content => {
      content.classList.toggle('active', content.id === tabName + 'Tab');
    });

    // Refresh tab content
    if (tabName === 'endpoints') {
      this.renderEndpoints();
    } else if (tabName === 'security') {
      this.renderFindings();
    } else if (tabName === 'ai') {
      this.renderPromptList('all');
      this.updateAITarget();
    }
  }

  updateAITarget() {
    // Set target from first request or inspected window
    if (this.requests.length > 0) {
      try {
        const url = new URL(this.requests[0].request.url);
        this.aiExportManager.setTarget(url.origin);
      } catch (e) {}
    }
  }

  saveSettings() {
    browser.storage.local.set({
      settings: {
        maxSizeMB: this.settings.maxSizeMB,
        autoStartOnDevTools: this.settings.autoSave
      }
    });
  }

  toggleRecording() {
    if (this.isRecording) {
      this.stopRecording();
    } else {
      this.startRecording();
    }
  }

  startRecording() {
    this.isRecording = true;
    this.elements.statusIndicator.classList.add('recording');
    this.elements.btnToggle.textContent = 'Stop';
    this.elements.btnToggle.classList.remove('btn-success');
    this.elements.btnToggle.classList.add('btn-danger');
    this.log('Recording started', 'success');
    this.syncStateToStorage();
  }

  stopRecording() {
    this.isRecording = false;
    this.elements.statusIndicator.classList.remove('recording');
    this.elements.btnToggle.textContent = 'Start';
    this.elements.btnToggle.classList.remove('btn-danger');
    this.elements.btnToggle.classList.add('btn-success');
    this.log('Recording stopped', 'info');
    this.syncStateToStorage();
  }

  async handleRequest(request) {
    if (!this.isRecording) return;

    // Domain filter
    if (this.settings.domainFilter) {
      try {
        const url = new URL(request.request.url);
        if (!url.hostname.toLowerCase().includes(this.settings.domainFilter)) {
          return;
        }
      } catch (e) {
        return;
      }
    }

    try {
      const entry = await this.buildHAREntry(request);
      const responseContent = entry.response.content?.text || '';

      // Security analysis
      const securityResults = await this.securityAnalyzer.analyze(entry, responseContent);

      // Skip if filtered or deduplicated
      if (securityResults?.filtered || securityResults?.deduplicated) {
        return;
      }

      // Store request
      this.requests.push(entry);

      // Calculate size
      const entrySize = JSON.stringify(entry).length;
      this.totalSize += entrySize;

      this.updateStats();
      this.updateProgress();

      // Notify background
      browser.runtime.sendMessage({
        action: 'updateStats',
        requestCount: this.requests.length,
        sizeMB: this.totalSize / (1024 * 1024)
      }).catch(() => {});

      // Auto-save threshold
      const sizeMB = this.totalSize / (1024 * 1024);
      if (this.settings.autoSave && sizeMB >= this.settings.maxSizeMB) {
        this.log(`Threshold ${this.settings.maxSizeMB} MB reached`, 'warning');
        await this.saveHAR();
      }
    } catch (e) {
      console.error('Error handling request:', e);
    }
  }

  async buildHAREntry(request) {
    const entry = {
      startedDateTime: new Date(request.startedDateTime).toISOString(),
      time: request.time,
      request: {
        method: request.request.method,
        url: request.request.url,
        httpVersion: request.request.httpVersion || 'HTTP/1.1',
        cookies: request.request.cookies || [],
        headers: request.request.headers || [],
        queryString: this.parseQueryString(request.request.url),
        postData: request.request.postData || undefined,
        headersSize: request.request.headersSize || -1,
        bodySize: request.request.bodySize || -1
      },
      response: {
        status: request.response.status,
        statusText: request.response.statusText,
        httpVersion: request.response.httpVersion || 'HTTP/1.1',
        cookies: request.response.cookies || [],
        headers: request.response.headers || [],
        content: {
          size: request.response.content?.size || 0,
          mimeType: request.response.content?.mimeType || 'application/octet-stream',
          text: ''
        },
        redirectURL: request.response.redirectURL || '',
        headersSize: request.response.headersSize || -1,
        bodySize: request.response.bodySize || -1
      },
      cache: {},
      timings: request.timings || {
        blocked: -1, dns: -1, connect: -1, send: 0, wait: 0, receive: 0
      },
      serverIPAddress: request.serverIPAddress || '',
      connection: request.connection || ''
    };

    if (this.settings.includeResponses && request.getContent) {
      try {
        const [content, encoding] = await new Promise((resolve) => {
          request.getContent((content, encoding) => resolve([content, encoding]));
        });
        if (content) {
          entry.response.content.text = content;
          entry.response.content.encoding = encoding || undefined;
        }
      } catch (e) { }
    }

    return entry;
  }

  parseQueryString(url) {
    try {
      const urlObj = new URL(url);
      const params = [];
      urlObj.searchParams.forEach((value, name) => params.push({ name, value }));
      return params;
    } catch {
      return [];
    }
  }

  updateStats() {
    this.elements.requestCount.textContent = this.requests.length;
    const sizeMB = this.totalSize / (1024 * 1024);
    this.elements.currentSize.textContent = sizeMB.toFixed(2);

    const sizeEl = this.elements.currentSize;
    sizeEl.classList.remove('warning', 'danger');
    if (sizeMB >= this.settings.maxSizeMB * 0.8) {
      sizeEl.classList.add('danger');
    } else if (sizeMB >= this.settings.maxSizeMB * 0.5) {
      sizeEl.classList.add('warning');
    }

    this.elements.savedCount.textContent = this.savedFilesCount;
  }

  updateProgress() {
    const sizeMB = this.totalSize / (1024 * 1024);
    const percent = Math.min((sizeMB / this.settings.maxSizeMB) * 100, 100);

    this.elements.progressFill.style.width = `${percent}%`;
    this.elements.progressText.textContent = `${sizeMB.toFixed(2)} / ${this.settings.maxSizeMB} MB`;

    const fill = this.elements.progressFill;
    fill.classList.remove('warning', 'danger');
    if (percent >= 80) fill.classList.add('danger');
    else if (percent >= 50) fill.classList.add('warning');
  }

  updateSecurityUI(summary) {
    // Update badges
    const totalIssues = summary.secrets.total + summary.issues.total;
    if (totalIssues > 0) {
      this.elements.securityBadge.textContent = totalIssues;
      this.elements.securityBadge.style.display = 'inline';
    }

    const endpointsCount = summary.endpoints.total;
    if (endpointsCount > 0) {
      this.elements.endpointsBadge.textContent = endpointsCount;
      this.elements.endpointsBadge.style.display = 'inline';
    }

    // Update security counts
    const severityCounts = {
      critical: summary.secrets.bySeverity.critical + summary.issues.bySeverity.critical,
      high: summary.secrets.bySeverity.high + summary.issues.bySeverity.high,
      medium: summary.secrets.bySeverity.medium + summary.issues.bySeverity.medium
    };

    this.elements.criticalCount.textContent = severityCounts.critical;
    this.elements.highCount.textContent = severityCounts.high;
    this.elements.mediumCount.textContent = severityCounts.medium;
    this.elements.secretsCount.textContent = summary.secrets.total;

    // Update endpoint stats
    this.elements.endpointsTotal.textContent = summary.endpoints.total;
    this.elements.idorTotal.textContent = summary.endpoints.idorCandidates;
    this.elements.jsEndpointsTotal.textContent = summary.jsEndpoints;

    const params = this.securityAnalyzer.getAllParameters();
    this.elements.paramsTotal.textContent = params.query.length + params.body.length;
  }

  renderFindings() {
    const secrets = this.securityAnalyzer.getSecrets();
    const issues = this.securityAnalyzer.getIssues();
    const allFindings = [...secrets, ...issues].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    });

    if (allFindings.length === 0) {
      this.elements.findingsList.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🔒</div>
          <div>No security findings yet</div>
          <div style="font-size:10px;margin-top:8px">Start capturing to analyze security issues</div>
        </div>
      `;
      return;
    }

    this.elements.findingsList.innerHTML = allFindings.slice(0, 100).map(finding => `
      <div class="finding-item ${finding.severity}">
        <div class="finding-header">
          <span class="finding-type">${finding.description || finding.type}</span>
          <span class="finding-severity" style="color:${this.getSeverityColor(finding.severity)}">${finding.severity?.toUpperCase()}</span>
        </div>
        <div class="finding-detail">
          ${finding.masked || finding.header || finding.cookieName || ''}
        </div>
        ${finding.request?.url ? `<div class="finding-url" title="${finding.request.url}">${this.truncateUrl(finding.request.url)}</div>` : ''}
        ${finding.decoded ? this.renderJWTInfo(finding.decoded) : ''}
      </div>
    `).join('');
  }

  renderJWTInfo(decoded) {
    if (decoded.error) return '';
    const expiredClass = decoded.expiration?.expired ? 'expired' : '';
    return `
      <div class="jwt-info">
        <div class="jwt-row"><strong>Alg:</strong> ${decoded.header?.alg || 'N/A'}</div>
        ${decoded.issuer ? `<div class="jwt-row"><strong>Issuer:</strong> ${decoded.issuer}</div>` : ''}
        ${decoded.expiration ? `<div class="jwt-row ${expiredClass}"><strong>Exp:</strong> ${decoded.expiration.date} ${decoded.expiration.expired ? '(EXPIRED)' : ''}</div>` : ''}
      </div>
    `;
  }

  renderEndpoints() {
    let endpoints = this.securityAnalyzer.getEndpoints();

    // Filter by search
    const search = this.elements.endpointSearch.value.toLowerCase();
    if (search) {
      endpoints = endpoints.filter(ep =>
        ep.normalizedPath.toLowerCase().includes(search) ||
        ep.host.toLowerCase().includes(search)
      );
    }

    // Filter by method
    const method = this.elements.methodFilter.value;
    if (method) {
      endpoints = endpoints.filter(ep => ep.method === method);
    }

    // Filter IDOR only
    if (this.elements.showIdorOnly.checked) {
      endpoints = endpoints.filter(ep => ep.idorIndicators && ep.idorIndicators.length > 0);
    }

    if (endpoints.length === 0) {
      this.elements.endpointsList.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🌐</div>
          <div>No endpoints${search || method ? ' matching filters' : ' captured yet'}</div>
        </div>
      `;
      return;
    }

    this.elements.endpointsList.innerHTML = endpoints.slice(0, 200).map(ep => {
      const hasIdor = ep.idorIndicators && ep.idorIndicators.length > 0;
      const idorScore = hasIdor ? Math.max(...ep.idorIndicators.map(i => i.confidence)) : 0;

      return `
        <div class="endpoint-item" title="${ep.fullUrl}">
          <span class="endpoint-method ${ep.method}">${ep.method}</span>
          <span class="endpoint-path">${ep.normalizedPath}</span>
          <div class="endpoint-meta">
            ${hasIdor ? `<span class="idor-indicator" title="IDOR score: ${(idorScore * 100).toFixed(0)}%">⚠ IDOR</span>` : ''}
            <span class="endpoint-count">${ep.requestCount}x</span>
          </div>
        </div>
      `;
    }).join('');
  }

  doExport(type) {
    let content = '';
    let filename = '';
    let mimeType = 'text/plain';

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

    switch (type) {
      case 'ffuf':
        content = this.securityAnalyzer.exportForFfuf({ normalized: true });
        filename = `endpoints-${timestamp}.txt`;
        break;
      case 'postman':
        content = this.securityAnalyzer.exportToPostman({ name: `AutoHAR Export ${timestamp}` });
        filename = `postman-${timestamp}.json`;
        mimeType = 'application/json';
        break;
      case 'curl':
        content = this.securityAnalyzer.exportToCurl(this.requests.slice(0, 50));
        filename = `curl-commands-${timestamp}.sh`;
        break;
      case 'params':
        content = this.securityAnalyzer.exportParamWordlist();
        filename = `params-${timestamp}.txt`;
        break;
      case 'markdown':
        content = this.securityAnalyzer.exportToMarkdown();
        filename = `security-report-${timestamp}.md`;
        mimeType = 'text/markdown';
        break;
      case 'json':
        content = this.securityAnalyzer.exportToJSON();
        filename = `autohar-data-${timestamp}.json`;
        mimeType = 'application/json';
        break;
      case 'nuclei':
        content = this.securityAnalyzer.exportNucleiTemplates();
        filename = `nuclei-templates-${timestamp}.yaml`;
        mimeType = 'text/yaml';
        break;
    }

    this.currentExport = { content, filename, mimeType };
    this.elements.exportOutput.value = content;
    this.log(`Export ${type} generated`, 'success');
  }

  async copyExportToClipboard() {
    if (!this.currentExport.content) {
      this.log('Nothing to copy', 'error');
      return;
    }

    try {
      await this.securityAnalyzer.copyToClipboard(this.currentExport.content);
      this.log('Copied to clipboard', 'success');
    } catch (e) {
      this.log('Copy failed', 'error');
    }
  }

  downloadExport() {
    if (!this.currentExport.content) {
      this.log('Nothing to download', 'error');
      return;
    }

    this.securityAnalyzer.download(
      this.currentExport.content,
      this.currentExport.filename,
      this.currentExport.mimeType
    );
    this.log(`Downloaded ${this.currentExport.filename}`, 'success');
  }

  async saveHAR() {
    if (this.requests.length === 0) {
      this.log('No requests to save', 'error');
      return;
    }

    const har = this.buildHAR();
    const sizeMB = this.totalSize / (1024 * 1024);

    let domain = 'capture';
    try {
      const inspectedUrl = await browser.devtools.inspectedWindow.eval('window.location.hostname');
      if (inspectedUrl && inspectedUrl[0]) {
        domain = inspectedUrl[0].replace(/[^a-zA-Z0-9.-]/g, '_');
      }
    } catch (e) {
      if (this.requests.length > 0) {
        try {
          const url = new URL(this.requests[0].request.url);
          domain = url.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
        } catch { }
      }
    }

    try {
      const result = await browser.runtime.sendMessage({
        action: 'saveHAR',
        data: har,
        metadata: { domain, sizeMB }
      });

      if (result.success) {
        this.savedFilesCount++;
        this.savedFiles.unshift({
          filename: result.filename,
          size: sizeMB,
          requests: this.requests.length,
          timestamp: new Date()
        });

        this.log(`Saved: ${result.filename} (${sizeMB.toFixed(2)} MB, ${this.requests.length} req)`, 'success');

        browser.runtime.sendMessage({
          action: 'notifySaved',
          filename: result.filename,
          sizeMB: sizeMB
        }).catch(() => {});

        // Reset
        this.requests = [];
        this.totalSize = 0;
        this.securityAnalyzer.clear();
        this.updateStats();
        this.updateProgress();
        this.updateSavedFilesList();
        this.syncStateToStorage();
      } else {
        this.log(`Error: ${result.error}`, 'error');
      }
    } catch (e) {
      this.log(`Save error: ${e.message}`, 'error');
    }
  }

  buildHAR() {
    return {
      log: {
        version: '1.2',
        creator: { name: 'PentestHAR', version: '2.0.0' },
        browser: {
          name: 'Firefox',
          version: navigator.userAgent.match(/Firefox\/(\d+)/)?.[1] || 'unknown'
        },
        pages: [{
          startedDateTime: this.requests[0]?.startedDateTime || new Date().toISOString(),
          id: 'page_1',
          title: 'AutoHAR Capture',
          pageTimings: { onContentLoad: -1, onLoad: -1 }
        }],
        entries: this.requests.map(entry => ({ ...entry, pageref: 'page_1' }))
      }
    };
  }

  clearCapture() {
    this.requests = [];
    this.totalSize = 0;
    this.securityAnalyzer.clear();
    this.updateStats();
    this.updateProgress();
    this.updateSecurityUI(this.securityAnalyzer.getSummary());
    this.renderFindings();
    this.renderEndpoints();
    this.log('Capture cleared', 'info');
    this.syncStateToStorage();

    browser.runtime.sendMessage({
      action: 'updateStats',
      requestCount: 0,
      sizeMB: 0
    }).catch(() => {});
  }

  updateSavedFilesList() {
    const container = this.elements.savedFiles;
    container.innerHTML = this.savedFiles.slice(0, 5).map(file => `
      <div class="saved-file">
        <span class="saved-file-name">${file.filename.split('/').pop()}</span>
        <span class="saved-file-size">${file.size.toFixed(2)} MB | ${file.requests} req</span>
      </div>
    `).join('');
  }

  syncStateToStorage() {
    const state = {
      isRecording: this.isRecording,
      requestCount: this.requests.length,
      totalSizeMB: this.totalSize / (1024 * 1024),
      savedCount: this.savedFilesCount,
      lastSavedFile: this.savedFiles[0] || null
    };
    browser.storage.local.set({ captureState: state });
  }

  getSeverityColor(severity) {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#f59e0b',
      low: '#3b82f6'
    };
    return colors[severity] || '#6b7280';
  }

  truncateUrl(url, maxLen = 60) {
    if (url.length <= maxLen) return url;
    return url.substring(0, maxLen - 3) + '...';
  }

  log(message, type = 'info') {
    const time = new Date().toLocaleTimeString('fr-FR', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
      <span class="log-time">${time}</span>
      <span class="log-message ${type}">${message}</span>
    `;

    this.elements.logContainer.insertBefore(entry, this.elements.logContainer.firstChild);

    while (this.elements.logContainer.children.length > 50) {
      this.elements.logContainer.removeChild(this.elements.logContainer.lastChild);
    }
  }

  // ========== AI Export Methods ==========

  aiDoExport(type) {
    this.updateAITarget();
    let content = '';
    let filename = '';

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

    switch (type) {
      case 'brief':
        content = this.aiExportManager.generateAIBrief();
        filename = `ai-brief-${timestamp}.md`;
        break;
      case 'scenarios':
        content = this.aiExportManager.generateAttackScenarios();
        filename = `attack-scenarios-${timestamp}.md`;
        break;
      case 'openapi':
        const endpoints = this.securityAnalyzer.getEndpoints();
        this.openAPIGenerator.generate(endpoints);
        content = this.openAPIGenerator.generateWithComments(endpoints);
        filename = `openapi-${timestamp}.yaml`;
        break;
      case 'chunked':
        const chunks = this.aiExportManager.generateChunkedExport();
        content = chunks.map(c => `# ${c.title}\n\n${c.content}`).join('\n\n---\n\n');
        filename = `chunked-export-${timestamp}.md`;
        break;
    }

    this.currentAIExport = { content, filename };
    this.elements.aiPromptOutput.value = content;
    this.updateTokenCount(content);
    this.selectedPromptId = null;
    this.log(`AI Export ${type} généré`, 'success');
  }

  renderPromptList(category = 'all') {
    const store = this.aiExportManager.promptStore;
    let prompts = category === 'all' ? store.getAll() : store.getByCategory(category);

    if (prompts.length === 0) {
      this.elements.promptList.innerHTML = `
        <div class="empty-state" style="padding:20px">
          <div>Aucun prompt dans cette catégorie</div>
        </div>
      `;
      return;
    }

    const categoryIcons = {
      recon: '🔍', idor: '🎯', auth: '🔐', secrets: '🔑',
      api: '🌐', offensive: '⚔️', reporting: '📝', custom: '✏️',
      prioritization: '📊'
    };

    this.elements.promptList.innerHTML = prompts.map(p => `
      <div class="prompt-item ${p.isDefault ? 'default' : ''} ${this.selectedPromptId === p.id ? 'selected' : ''}"
           data-id="${p.id}">
        <div class="prompt-icon">${categoryIcons[p.category] || '📄'}</div>
        <div class="prompt-info">
          <div class="prompt-name">${p.name}</div>
          <div class="prompt-desc">${p.description || ''}</div>
        </div>
        <div class="prompt-actions">
          ${!p.isDefault ? `<button class="prompt-action-btn" data-action="delete" title="Supprimer">🗑️</button>` : ''}
          <button class="prompt-action-btn" data-action="copy" title="Copier">📋</button>
        </div>
      </div>
    `).join('');

    // Bind click events
    this.elements.promptList.querySelectorAll('.prompt-item').forEach(item => {
      item.addEventListener('click', (e) => {
        const action = e.target.closest('[data-action]')?.dataset.action;
        const id = item.dataset.id;

        if (action === 'delete') {
          this.aiDeletePrompt(id);
        } else if (action === 'copy') {
          this.aiSelectAndCopyPrompt(id);
        } else {
          this.aiSelectPrompt(id);
        }
      });
    });
  }

  aiSelectPrompt(id) {
    this.selectedPromptId = id;
    this.updateAITarget();

    const rendered = this.aiExportManager.getRenderedPrompt(id);
    if (rendered) {
      this.elements.aiPromptOutput.value = rendered.renderedPrompt;
      this.currentAIExport = {
        content: rendered.renderedPrompt,
        filename: `prompt-${rendered.name.toLowerCase().replace(/\s+/g, '-')}.md`
      };
      this.updateTokenCount(rendered.renderedPrompt);
    }

    // Update UI selection
    this.elements.promptList.querySelectorAll('.prompt-item').forEach(item => {
      item.classList.toggle('selected', item.dataset.id === id);
    });
  }

  async aiSelectAndCopyPrompt(id) {
    this.aiSelectPrompt(id);
    await this.aiCopyPrompt();
  }

  async aiCopyPrompt() {
    const content = this.elements.aiPromptOutput.value;
    if (!content) {
      this.log('Rien à copier', 'error');
      return;
    }

    try {
      await navigator.clipboard.writeText(content);
      this.log('Prompt copié dans le presse-papier', 'success');
    } catch (e) {
      // Fallback
      const textarea = document.createElement('textarea');
      textarea.value = content;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      this.log('Prompt copié', 'success');
    }
  }

  aiDownloadPrompt() {
    const content = this.elements.aiPromptOutput.value;
    if (!content) {
      this.log('Rien à télécharger', 'error');
      return;
    }

    const filename = this.currentAIExport?.filename || 'prompt.md';
    this.securityAnalyzer.download(content, filename, 'text/markdown');
    this.log(`Téléchargé: ${filename}`, 'success');
  }

  aiDeletePrompt(id) {
    const store = this.aiExportManager.promptStore;
    const prompt = store.getById(id);

    if (prompt?.isDefault) {
      this.log('Impossible de supprimer un prompt par défaut', 'error');
      return;
    }

    if (confirm(`Supprimer le prompt "${prompt?.name}" ?`)) {
      store.delete(id);
      this.renderPromptList(this.getActiveCategory());
      this.log('Prompt supprimé', 'success');
    }
  }

  aiEditCurrentPrompt() {
    if (!this.selectedPromptId) {
      // Create new prompt with current content
      this.aiShowPromptModal();
      this.elements.promptContent.value = this.elements.aiPromptOutput.value;
      return;
    }

    const prompt = this.aiExportManager.promptStore.getById(this.selectedPromptId);
    if (prompt) {
      this.aiShowPromptModal(prompt);
    }
  }

  aiShowPromptModal(existingPrompt = null) {
    this.editingPromptId = existingPrompt?.id || null;

    this.elements.promptModalTitle.textContent = existingPrompt ? 'Modifier le Prompt' : 'Nouveau Prompt';
    this.elements.promptName.value = existingPrompt?.name || '';
    this.elements.promptCategory.value = existingPrompt?.category || 'custom';
    this.elements.promptDescription.value = existingPrompt?.description || '';
    this.elements.promptContent.value = existingPrompt?.prompt || '';

    this.elements.promptModal.classList.add('active');
  }

  aiHidePromptModal() {
    this.elements.promptModal.classList.remove('active');
    this.editingPromptId = null;
  }

  aiSavePrompt() {
    const store = this.aiExportManager.promptStore;
    const promptData = {
      name: this.elements.promptName.value.trim(),
      category: this.elements.promptCategory.value,
      description: this.elements.promptDescription.value.trim(),
      prompt: this.elements.promptContent.value.trim()
    };

    const validation = store.validate(promptData);
    if (!validation.valid) {
      this.log(validation.errors[0], 'error');
      return;
    }

    if (this.editingPromptId) {
      store.update(this.editingPromptId, promptData);
      this.log('Prompt mis à jour', 'success');
    } else {
      const newPrompt = store.add(promptData);
      this.selectedPromptId = newPrompt.id;
      this.log('Prompt créé', 'success');
    }

    this.aiHidePromptModal();
    this.renderPromptList(this.getActiveCategory());
  }

  getActiveCategory() {
    const active = this.elements.categoryPills.querySelector('.category-pill.active');
    return active?.dataset.category || 'all';
  }

  updateTokenCount(content) {
    // Rough estimation: 1 token ~= 4 characters
    const tokens = Math.ceil(content.length / 4);
    let display = '';

    if (tokens < 1000) {
      display = `~${tokens} tokens`;
    } else {
      display = `~${(tokens / 1000).toFixed(1)}k tokens`;
    }

    // Add warning if over context limits
    if (tokens > 100000) {
      display += ' ⚠️ Très long';
    } else if (tokens > 30000) {
      display += ' ⚠️ Long';
    }

    this.elements.tokenCount.textContent = display;
  }
}

// Initialize
const autoHAR = new AutoHARCapture();
