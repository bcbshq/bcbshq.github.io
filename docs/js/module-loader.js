// docs/js/module-loader.js
class ModuleLoader {
  constructor() {
    this.modules = new Map();
    this.dataCache = new Map();
    this.refreshInterval = 300000; // 5 minutes
  }
  
  async loadModule(name) {
    if (!this.modules.has(name)) {
      const module = await import(`/modules/${name}/module.js`);
      this.modules.set(name, new module.default());
    }
    return this.modules.get(name);
  }
  
  async loadData(dataType) {
    const cacheKey = dataType;
    const cached = this.dataCache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < this.refreshInterval) {
      return cached.data;
    }
    
    try {
      const response = await fetch(`/data/processed/${dataType}.json`);
      const data = await response.json();
      
      this.dataCache.set(cacheKey, {
        data: data,
        timestamp: Date.now()
      });
      
      return data;
    } catch (error) {
      console.error(`Failed to load ${dataType}:`, error);
      return cached?.data || null;
    }
  }
  
  async renderTab(tabName) {
    const module = await this.loadModule(tabName);
    const data = await this.loadData(tabName);
    
    if (module && data) {
      module.setData(data);
      module.render(document.getElementById(`${tabName}-container`));
    }
  }
  
  async initialize() {
    // Load metadata
    const metadata = await this.loadData('metadata');
    this.displayMetadata(metadata);
    
    // Load initial tab
    await this.renderTab('threat-actors');
    
    // Setup tab switching
    document.querySelectorAll('.tab-button').forEach(button => {
      button.addEventListener('click', async (e) => {
        const tabName = e.target.dataset.tab;
        await this.renderTab(tabName);
      });
    });
    
    // Setup auto-refresh
    setInterval(() => this.refresh(), this.refreshInterval);
  }
  
  async refresh() {
    // Clear cache to force reload
    this.dataCache.clear();
    
    // Reload current tab
    const activeTab = document.querySelector('.tab-button.active');
    if (activeTab) {
      await this.renderTab(activeTab.dataset.tab);
    }
  }
  
  displayMetadata(metadata) {
    const element = document.getElementById('dashboard-metadata');
    if (!element || !metadata) return;
    
    element.innerHTML = `
      <div class="metadata-card">
        <h3>Data Statistics</h3>
        <p>Last Updated: ${new Date(metadata.processedDate).toLocaleString()}</p>
        <p>Reporting Period: ${metadata.period}</p>
        <p>Contributing Teams: ${metadata.subsidiaries.length}</p>
        <div class="record-counts">
          <span>Threat Actors: ${metadata.recordCounts.threatActors}</span>
          <span>Malware: ${metadata.recordCounts.malware}</span>
          <span>Techniques: ${metadata.recordCounts.techniques}</span>
          <span>Incidents: ${metadata.recordCounts.incidents}</span>
        </div>
      </div>
    `;
  }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  const loader = new ModuleLoader();
  loader.initialize();
});