// modules/core/transformers.js
const { v4: uuidv4 } = require('uuid');

class DataTransformers {
  normalizeActors(actors) {
    return actors.map(actor => ({
      ...actor,
      id: actor.id || this.generateUUID(),
      name: this.normalizeName(actor.name),
      type: this.normalizeActorType(actor.type),
      lastUpdated: new Date().toISOString(),
      confidence: actor.confidence || this.calculateConfidence(actor),
      aliases: this.normalizeAliases(actor.aliases),
      ttps: this.normalizeTTPs(actor.ttps)
    }));
  }

  normalizeMalware(malware) {
    return malware.map(m => ({
      ...m,
      id: m.id || this.generateUUID(),
      name: this.normalizeName(m.name),
      family: m.family || this.inferFamily(m.name),
      type: this.normalizeMalwareType(m.type),
      lastUpdated: new Date().toISOString(),
      capabilities: this.normalizeCapabilities(m.capabilities),
      iocs: this.normalizeIOCs(m.iocs)
    }));
  }

  normalizeTechniques(techniques) {
    return techniques.map(t => ({
      ...t,
      techniqueId: this.normalizeTechniqueId(t.techniqueId),
      tactic: this.normalizeTactics(t.tactic),
      lastObserved: t.observedDate || new Date().toISOString(),
      aggregatedFrequency: t.frequency || 1,
      severity: this.normalizeSeverity(t.severity)
    }));
  }

  normalizeIncidents(incidents) {
    return incidents.map(i => ({
      ...i,
      id: i.id || this.generateUUID(),
      impactScore: this.calculateImpactScore(i),
      duration: this.calculateDuration(i),
      sector: this.normalizeSector(i.sector),
      attackType: this.normalizeAttackType(i.attackType),
      lastUpdated: new Date().toISOString()
    }));
  }

  normalizeVectors(vectors) {
    return vectors.map(v => ({
      ...v,
      vectorType: this.normalizeVectorType(v.vectorType),
      riskScore: this.calculateRiskScore(v),
      severity: this.normalizeSeverity(v.severity),
      lastUpdated: new Date().toISOString()
    }));
  }

  // Helper methods
  generateUUID() {
    return uuidv4();
  }

  normalizeName(name) {
    if (!name) return 'Unknown';
    return name.trim()
      .replace(/\s+/g, ' ')
      .replace(/[^\w\s\-\.]/g, '');
  }

  normalizeActorType(type) {
    if (!type) return 'unknown';
    
    const typeMap = {
      'ransomware': 'ransomware',
      'ransomware group': 'ransomware',
      'ransomware-as-a-service': 'ransomware',
      'raas': 'ransomware',
      'nation-state': 'apt',
      'nation state': 'apt',
      'apt': 'apt',
      'advanced persistent threat': 'apt',
      'financial': 'financial',
      'financial crime': 'financial',
      'crimeware': 'crimeware',
      'criminal': 'crimeware',
      'hacktivist': 'hacktivist',
      'insider': 'insider',
      'insider threat': 'insider'
    };
    
    const normalized = type.toLowerCase().trim();
    return typeMap[normalized] || 'unknown';
  }

  normalizeMalwareType(type) {
    if (!type) return 'unknown';
    
    const typeMap = {
      'ransomware': 'ransomware',
      'trojan': 'trojan',
      'banking trojan': 'trojan',
      'backdoor': 'backdoor',
      'loader': 'loader',
      'dropper': 'loader',
      'infostealer': 'infostealer',
      'stealer': 'infostealer',
      'rat': 'rat',
      'remote access trojan': 'rat',
      'worm': 'worm',
      'rootkit': 'rootkit',
      'botnet': 'botnet',
      'miner': 'miner',
      'cryptominer': 'miner'
    };
    
    const normalized = type.toLowerCase().trim();
    return typeMap[normalized] || 'other';
  }

  normalizeAliases(aliases) {
    if (!aliases) return [];
    if (!Array.isArray(aliases)) return [aliases];
    
    return aliases
      .filter(a => a && typeof a === 'string')
      .map(a => this.normalizeName(a))
      .filter(a => a && a !== 'Unknown');
  }

  normalizeTTPs(ttps) {
    if (!ttps) return [];
    if (!Array.isArray(ttps)) return [ttps];
    
    return ttps
      .filter(t => t)
      .map(t => {
        // If it's already a technique ID, normalize it
        if (/^T\d{4}/i.test(t)) {
          return this.normalizeTechniqueId(t);
        }
        // Otherwise keep as is (might be a description)
        return String(t).trim();
      });
  }

  normalizeTechniqueId(id) {
    if (!id) return null;
    
    // Ensure proper format: T#### or T####.###
    const match = String(id).toUpperCase().match(/T(\d{4})(\.\d{3})?/);
    if (match) {
      return match[0];
    }
    return null;
  }

  normalizeTactics(tactics) {
    const validTactics = [
      'Initial Access',
      'Execution',
      'Persistence',
      'Privilege Escalation',
      'Defense Evasion',
      'Credential Access',
      'Discovery',
      'Lateral Movement',
      'Collection',
      'Command and Control',
      'Exfiltration',
      'Impact'
    ];
    
    if (!tactics) return [];
    if (!Array.isArray(tactics)) tactics = [tactics];
    
    return tactics
      .map(t => {
        if (!t) return null;
        const normalized = t.split(/[,;]/)
          .map(part => {
            const trimmed = part.trim();
            // Find matching tactic (case-insensitive)
            return validTactics.find(vt => 
              vt.toLowerCase() === trimmed.toLowerCase()
            );
          })
          .filter(Boolean);
        return normalized;
      })
      .flat()
      .filter((t, i, arr) => arr.indexOf(t) === i); // Unique values
  }

  normalizeCapabilities(capabilities) {
    if (!capabilities) return [];
    if (!Array.isArray(capabilities)) return [capabilities];
    
    return capabilities
      .filter(c => c && typeof c === 'string')
      .map(c => c.trim())
      .filter((c, i, arr) => arr.indexOf(c) === i); // Unique values
  }

  normalizeIOCs(iocs) {
    if (!iocs) return { hashes: [], domains: [], ips: [], urls: [] };
    
    const normalized = {
      hashes: [],
      domains: [],
      ips: [],
      urls: []
    };
    
    if (iocs.hashes && Array.isArray(iocs.hashes)) {
      normalized.hashes = iocs.hashes.filter(h => h && typeof h === 'string');
    }
    
    if (iocs.domains && Array.isArray(iocs.domains)) {
      normalized.domains = iocs.domains
        .filter(d => d && typeof d === 'string')
        .map(d => d.toLowerCase().replace(/\[.\]/g, '.'));
    }
    
    if (iocs.ips && Array.isArray(iocs.ips)) {
      normalized.ips = iocs.ips.filter(ip => ip && typeof ip === 'string');
    }
    
    if (iocs.urls && Array.isArray(iocs.urls)) {
      normalized.urls = iocs.urls
        .filter(url => url && typeof url === 'string')
        .map(url => url.replace(/\[.\]/g, '.'));
    }
    
    return normalized;
  }

  normalizeSector(sector) {
    if (!sector) return 'unknown';
    
    const sectorMap = {
      'hospital': 'hospital',
      'hospitals': 'hospital',
      'healthcare provider': 'hospital',
      'insurance': 'insurance',
      'health insurance': 'insurance',
      'payer': 'insurance',
      'pharma': 'pharma',
      'pharmaceutical': 'pharma',
      'medical device': 'medical_device',
      'medical devices': 'medical_device',
      'clinic': 'clinic',
      'laboratory': 'laboratory',
      'lab': 'laboratory'
    };
    
    const normalized = sector.toLowerCase().trim();
    return sectorMap[normalized] || 'other';
  }

  normalizeAttackType(type) {
    if (!type) return 'unknown';
    
    const typeMap = {
      'ransomware': 'ransomware',
      'data breach': 'data_breach',
      'breach': 'data_breach',
      'supply chain': 'supply_chain',
      'supply-chain': 'supply_chain',
      'insider': 'insider',
      'insider threat': 'insider',
      'phishing': 'phishing',
      'bec': 'phishing',
      'business email compromise': 'phishing',
      'ddos': 'ddos',
      'denial of service': 'ddos',
      'malware': 'malware',
      'cryptojacking': 'cryptojacking',
      'data theft': 'data_breach'
    };
    
    const normalized = type.toLowerCase().trim();
    return typeMap[normalized] || 'other';
  }

  normalizeVectorType(type) {
    if (!type) return 'unknown';
    return type.toLowerCase().replace(/[^a-z0-9]+/g, '_');
  }

  normalizeSeverity(severity) {
    if (!severity) return 'medium';
    
    const severityMap = {
      'critical': 'critical',
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'info': 'low',
      'informational': 'low',
      'none': 'low',
      'unknown': 'medium'
    };
    
    const normalized = severity.toLowerCase().trim();
    return severityMap[normalized] || 'medium';
  }

  inferFamily(malwareName) {
    if (!malwareName) return 'Unknown';
    
    const families = {
      'lockbit': 'LockBit',
      'blackcat': 'BlackCat/ALPHV',
      'alphv': 'BlackCat/ALPHV',
      'conti': 'Conti',
      'ryuk': 'Ryuk',
      'revil': 'REvil',
      'sodinokibi': 'REvil',
      'maze': 'Maze',
      'egregor': 'Egregor',
      'darkside': 'DarkSide',
      'avaddon': 'Avaddon',
      'babuk': 'Babuk',
      'clop': 'Clop',
      'ragnarlocker': 'RagnarLocker',
      'ragnar': 'RagnarLocker',
      'hive': 'Hive',
      'blackbasta': 'BlackBasta',
      'basta': 'BlackBasta',
      'royal': 'Royal',
      'play': 'Play',
      'medusa': 'Medusa',
      'akira': 'Akira',
      'bianlian': 'BianLian',
      'qilin': 'QiLin',
      'agenda': 'QiLin',
      'inc': 'INC Ransomware',
      'ransomhub': 'RansomHub',
      'interlock': 'Interlock',
      'daixin': 'Daixin Team',
      'vice society': 'Vice Society',
      'karakurt': 'Karakurt'
    };
    
    const nameLower = malwareName.toLowerCase();
    for (const [key, family] of Object.entries(families)) {
      if (nameLower.includes(key)) {
        return family;
      }
    }
    
    // If no match found, return the original name cleaned up
    return malwareName.trim();
  }

  calculateConfidence(actor) {
    let score = 50; // Base score
    
    // Add points for various data completeness factors
    if (actor.ttps && actor.ttps.length > 0) score += 10;
    if (actor.ttps && actor.ttps.length > 3) score += 5;
    if (actor.ttps && actor.ttps.length > 5) score += 5;
    
    if (actor.malwareUsed && actor.malwareUsed.length > 0) score += 10;
    if (actor.malwareUsed && actor.malwareUsed.length > 2) score += 5;
    
    if (actor.infrastructure && actor.infrastructure.length > 0) score += 10;
    
    if (actor.healthcareTargets && actor.healthcareTargets > 0) score += 10;
    if (actor.healthcareTargets && actor.healthcareTargets > 5) score += 5;
    if (actor.healthcareTargets && actor.healthcareTargets > 10) score += 5;
    
    if (actor.aliases && actor.aliases.length > 0) score += 5;
    
    if (actor.motivation && actor.motivation !== 'unknown') score += 5;
    
    if (actor.origin && actor.origin !== 'Unknown') score += 5;
    
    return Math.min(100, score);
  }

  calculateImpactScore(incident) {
    let score = 0;
    
    // Financial impact scoring (0-40 points)
    if (incident.financialImpact) {
      if (incident.financialImpact >= 100000000) score += 40; // >= $100M
      else if (incident.financialImpact >= 50000000) score += 38; // >= $50M
      else if (incident.financialImpact >= 10000000) score += 35; // >= $10M
      else if (incident.financialImpact >= 5000000) score += 32; // >= $5M
      else if (incident.financialImpact >= 1000000) score += 30; // >= $1M
      else if (incident.financialImpact >= 500000) score += 25; // >= $500K
      else if (incident.financialImpact >= 100000) score += 20; // >= $100K
      else if (incident.financialImpact >= 50000) score += 15; // >= $50K
      else if (incident.financialImpact >= 10000) score += 10; // >= $10K
      else if (incident.financialImpact > 0) score += 5;
    }
    
    // Operational impact scoring (0-30 points)
    if (incident.operationalImpact) {
      // Downtime scoring
      if (incident.operationalImpact.downtime) {
        if (incident.operationalImpact.downtime >= 720) score += 20; // >= 30 days
        else if (incident.operationalImpact.downtime >= 168) score += 18; // >= 1 week
        else if (incident.operationalImpact.downtime >= 72) score += 15; // >= 3 days
        else if (incident.operationalImpact.downtime >= 48) score += 12; // >= 2 days
        else if (incident.operationalImpact.downtime >= 24) score += 10; // >= 1 day
        else if (incident.operationalImpact.downtime >= 8) score += 7; // >= 8 hours
        else if (incident.operationalImpact.downtime > 0) score += 5;
      }
      
      // Systems affected scoring
      if (incident.operationalImpact.systemsAffected) {
        if (incident.operationalImpact.systemsAffected >= 1000) score += 10;
        else if (incident.operationalImpact.systemsAffected >= 500) score += 8;
        else if (incident.operationalImpact.systemsAffected >= 100) score += 6;
        else if (incident.operationalImpact.systemsAffected >= 50) score += 4;
        else if (incident.operationalImpact.systemsAffected >= 10) score += 2;
      }
    }
    
    // Patient care impact scoring (0-30 points)
    const careImpactScores = {
      'critical': 30,
      'severe': 25,
      'moderate': 15,
      'minimal': 5,
      'none': 0,
      'unknown': 0
    };
    
    const careImpact = incident.patientCareImpact || 'unknown';
    score += careImpactScores[careImpact.toLowerCase()] || 0;
    
    // Records compromised bonus (0-10 points)
    if (incident.recordsCompromised) {
      if (incident.recordsCompromised >= 10000000) score += 10; // >= 10M records
      else if (incident.recordsCompromised >= 1000000) score += 8; // >= 1M records
      else if (incident.recordsCompromised >= 100000) score += 6; // >= 100K records
      else if (incident.recordsCompromised >= 10000) score += 4; // >= 10K records
      else if (incident.recordsCompromised >= 1000) score += 2; // >= 1K records
      else if (incident.recordsCompromised > 0) score += 1;
    }
    
    return Math.min(100, score);
  }

  calculateDuration(incident) {
    // Try different date combinations to calculate duration
    let startDate, endDate;
    
    if (incident.discoveryDate && incident.containmentDate) {
      startDate = new Date(incident.discoveryDate);
      endDate = new Date(incident.containmentDate);
    } else if (incident.incidentDate && incident.containmentDate) {
      startDate = new Date(incident.incidentDate);
      endDate = new Date(incident.containmentDate);
    } else if (incident.incidentDate && incident.resolutionDate) {
      startDate = new Date(incident.incidentDate);
      endDate = new Date(incident.resolutionDate);
    } else {
      return null;
    }
    
    // Validate dates
    if (isNaN(startDate) || isNaN(endDate)) {
      return null;
    }
    
    // Calculate duration in hours
    const durationMs = endDate - startDate;
    const durationHours = Math.round(durationMs / (1000 * 60 * 60));
    
    // Return duration only if positive
    return durationHours > 0 ? durationHours : null;
  }

  calculateRiskScore(vector) {
    let score = 0;
    
    // Base score from severity (0-40 points)
    const severityScores = {
      'critical': 40,
      'high': 30,
      'medium': 20,
      'low': 10
    };
    
    score += severityScores[vector.severity] || 20;
    
    // Frequency component (0-30 points)
    if (vector.frequency) {
      if (vector.frequency >= 100) score += 30;
      else if (vector.frequency >= 50) score += 25;
      else if (vector.frequency >= 20) score += 20;
      else if (vector.frequency >= 10) score += 15;
      else if (vector.frequency >= 5) score += 10;
      else if (vector.frequency > 0) score += 5;
    }
    
    // Actor usage component (0-20 points)
    if (vector.actorsUsing && Array.isArray(vector.actorsUsing)) {
      const actorCount = vector.actorsUsing.length;
      if (actorCount >= 20) score += 20;
      else if (actorCount >= 10) score += 15;
      else if (actorCount >= 5) score += 10;
      else if (actorCount >= 2) score += 5;
      else if (actorCount > 0) score += 2;
    }
    
    // Targeted assets component (0-10 points)
    if (vector.targetedAssets && Array.isArray(vector.targetedAssets)) {
      const criticalAssets = [
        'ehr', 'electronic health records',
        'medical devices', 'medical device',
        'patient data', 'phi',
        'backup', 'backups',
        'domain controller', 'active directory',
        'payment', 'billing'
      ];
      
      const targetedCritical = vector.targetedAssets.some(asset => 
        criticalAssets.some(critical => 
          asset.toLowerCase().includes(critical)
        )
      );
      
      if (targetedCritical) score += 10;
      else if (vector.targetedAssets.length > 0) score += 5;
    }
    
    return Math.min(100, score);
  }
}

module.exports = { DataTransformers };