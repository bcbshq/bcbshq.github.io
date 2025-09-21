// modules/core/aggregators.js

class DataAggregators {
  deduplicateActors(actors, strategy = 'merge') {
    const unique = new Map();
    
    for (const actor of actors) {
      const key = this.getActorKey(actor);
      
      if (!unique.has(key)) {
        unique.set(key, actor);
      } else if (strategy === 'merge') {
        const existing = unique.get(key);
        unique.set(key, this.mergeActors(existing, actor));
      } else if (strategy === 'latest') {
        const existing = unique.get(key);
        if (new Date(actor.telemetryDate) > new Date(existing.telemetryDate)) {
          unique.set(key, actor);
        }
      } else if (strategy === 'aggregate') {
        const existing = unique.get(key);
        unique.set(key, this.aggregateActor(existing, actor));
      }
    }
    
    return Array.from(unique.values());
  }

  deduplicateMalware(malware, strategy = 'merge') {
    const unique = new Map();
    
    for (const m of malware) {
      const key = `${m.name}-${m.family || ''}`.toLowerCase();
      
      if (!unique.has(key)) {
        unique.set(key, m);
      } else if (strategy === 'merge') {
        const existing = unique.get(key);
        unique.set(key, this.mergeMalware(existing, m));
      } else if (strategy === 'latest') {
        const existing = unique.get(key);
        if (new Date(m.telemetryDate) > new Date(existing.telemetryDate)) {
          unique.set(key, m);
        }
      }
    }
    
    return Array.from(unique.values());
  }

  deduplicateTechniques(techniques, strategy = 'aggregate') {
    const unique = new Map();
    
    for (const t of techniques) {
      const key = t.techniqueId;
      
      if (!unique.has(key)) {
        t.orgsReporting = [t.org];
        unique.set(key, t);
      } else if (strategy === 'aggregate') {
        const existing = unique.get(key);
        existing.aggregatedFrequency = (existing.aggregatedFrequency || 1) + (t.frequency || 1);
        existing.orgsReporting = [
          ...new Set([...(existing.orgsReporting || []), t.org])
        ];
        // Keep the highest severity
        if (this.compareSeverity(t.severity, existing.severity) > 0) {
          existing.severity = t.severity;
        }
        // Merge detection methods and mitigations
        existing.detectionMethods = [
          ...new Set([...(existing.detectionMethods || []), ...(t.detectionMethods || [])])
        ];
        existing.mitigationStrategies = [
          ...new Set([...(existing.mitigationStrategies || []), ...(t.mitigationStrategies || [])])
        ];
        unique.set(key, existing);
      }
    }
    
    return Array.from(unique.values());
  }

  deduplicateIncidents(incidents, strategy = 'unique') {
    // Incidents are typically unique, but check for duplicates by ID
    const unique = new Map();
    
    for (const i of incidents) {
      const key = i.id;
      if (!unique.has(key)) {
        unique.set(key, i);
      } else if (strategy === 'merge') {
        // If same incident reported by multiple orgs, merge details
        const existing = unique.get(key);
        unique.set(key, this.mergeIncidents(existing, i));
      }
    }
    
    return Array.from(unique.values());
  }

  deduplicateVectors(vectors, strategy = 'aggregate') {
    const unique = new Map();
    
    for (const v of vectors) {
      const key = v.vectorType;
      
      if (!unique.has(key)) {
        v.orgsReporting = [v.org];
        unique.set(key, v);
      } else if (strategy === 'aggregate') {
        const existing = unique.get(key);
        existing.frequency = (existing.frequency || 0) + (v.frequency || 1);
        existing.methods = [...new Set([...(existing.methods || []), ...(v.methods || [])])];
        existing.actorsUsing = [...new Set([...(existing.actorsUsing || []), ...(v.actorsUsing || [])])];
        existing.targetedAssets = [...new Set([...(existing.targetedAssets || []), ...(v.targetedAssets || [])])];
        existing.orgsReporting = [
          ...new Set([...(existing.orgsReporting || []), v.org])
        ];
        unique.set(key, existing);
      }
    }
    
    return Array.from(unique.values());
  }

  // Aggregation methods
  aggregateActors(actors, period = 'monthly') {
    const aggregated = actors.map(actor => ({
      ...actor,
      reportingPeriod: this.getPeriod(actor.telemetryDate, period),
      orgsReporting: actor.orgsReporting || [actor.org],
      observationCount: 1
    }));
    
    return this.sortByThreatLevel(aggregated);
  }

  aggregateMalware(malware, period = 'monthly') {
    return malware.map(m => ({
      ...m,
      reportingPeriod: this.getPeriod(m.telemetryDate, period),
      prevalence: this.calculatePrevalence(malware, m.name),
      orgsReporting: m.orgsReporting || [m.org]
    }));
  }

  aggregateTechniques(techniques, period = 'monthly') {
    // Already aggregated in deduplication
    return techniques.map(t => ({
      ...t,
      reportingPeriod: this.getPeriod(t.telemetryDate || new Date(), period),
      averageSeverity: t.severity || 'medium',
      prevalenceScore: (t.aggregatedFrequency / techniques.length) * 100
    })).sort((a, b) => b.aggregatedFrequency - a.aggregatedFrequency);
  }

  aggregateIncidents(incidents, period = 'monthly') {
    // Group incidents by period
    const byPeriod = this.groupBy(incidents, i => 
      this.getPeriod(i.incidentDate || i.telemetryDate, period)
    );
    
    const aggregated = [];
    
    for (const [periodKey, periodIncidents] of Object.entries(byPeriod)) {
      aggregated.push({
        period: periodKey,
        totalIncidents: periodIncidents.length,
        incidents: periodIncidents,
        statistics: {
          byType: this.countBy(periodIncidents, 'attackType'),
          bySector: this.countBy(periodIncidents, 'sector'),
          bySeverity: this.countBy(periodIncidents, i => {
            const score = i.impactScore || 0;
            if (score >= 75) return 'critical';
            if (score >= 50) return 'high';
            if (score >= 25) return 'medium';
            return 'low';
          }),
          totalRecordsCompromised: periodIncidents.reduce((sum, i) => sum + (i.recordsCompromised || 0), 0),
          totalFinancialImpact: periodIncidents.reduce((sum, i) => sum + (i.financialImpact || 0), 0),
          averageDowntime: this.average(
            periodIncidents.map(i => i.operationalImpact?.downtime || i.duration).filter(Boolean)
          ),
          criticalIncidents: periodIncidents.filter(i => i.patientCareImpact === 'critical').length
        }
      });
    }
    
    return aggregated;
  }

  aggregateVectors(vectors, period = 'monthly') {
    return vectors.map(v => ({
      ...v,
      reportingPeriod: this.getPeriod(v.telemetryDate || new Date(), period),
      prevalenceScore: this.calculateVectorPrevalence(vectors, v.vectorType),
      aggregatedFrequency: v.frequency || 1
    })).sort((a, b) => b.riskScore - a.riskScore);
  }

  generateMappings(data) {
    const mappings = [];
    
    // Create actor -> malware -> technique mappings
    for (const actor of data.threatActors) {
      const actorMappings = {
        actorId: actor.id,
        actorName: actor.name,
        actorType: actor.type,
        malware: [],
        techniques: [],
        incidents: []
      };
      
      // Find malware associated with this actor
      for (const malware of data.malware) {
        if (malware.associatedActors && malware.associatedActors.includes(actor.name)) {
          actorMappings.malware.push({
            id: malware.id,
            name: malware.name,
            type: malware.type
          });
        }
      }
      
      // Find techniques used by this actor
      for (const technique of data.techniques) {
        if (technique.actorId === actor.id || 
            (actor.ttps && actor.ttps.includes(technique.techniqueId))) {
          actorMappings.techniques.push({
            id: technique.techniqueId,
            name: technique.name,
            tactic: technique.tactic,
            frequency: technique.aggregatedFrequency
          });
        }
      }
      
      // Find incidents attributed to this actor
      for (const incident of data.incidents) {
        if (incident.actorId === actor.id || incident.actor === actor.name) {
          actorMappings.incidents.push({
            id: incident.id,
            date: incident.incidentDate,
            impact: incident.impactScore
          });
        }
      }
      
      if (actorMappings.malware.length > 0 || 
          actorMappings.techniques.length > 0 || 
          actorMappings.incidents.length > 0) {
        mappings.push(actorMappings);
      }
    }
    
    return mappings;
  }

  // Helper methods
  getActorKey(actor) {
    // Create unique key for actor deduplication
    const name = (actor.name || '').toLowerCase().trim();
    const aliases = (actor.aliases || []).map(a => a.toLowerCase().trim()).sort().join('|');
    return `${name}|${aliases}`;
  }

  mergeActors(existing, newActor) {
    return {
      ...existing,
      ...newActor,
      id: existing.id, // Keep existing ID
      aliases: [...new Set([...(existing.aliases || []), ...(newActor.aliases || [])])],
      ttps: [...new Set([...(existing.ttps || []), ...(newActor.ttps || [])])],
      malwareUsed: [...new Set([...(existing.malwareUsed || []), ...(newActor.malwareUsed || [])])],
      healthcareTargets: Math.max(existing.healthcareTargets || 0, newActor.healthcareTargets || 0),
      confidence: Math.max(existing.confidence || 0, newActor.confidence || 0),
      firstSeen: this.earliestDate(existing.firstSeen, newActor.firstSeen),
      lastSeen: this.latestDate(existing.lastSeen, newActor.lastSeen),
      orgsReporting: [...new Set([
        ...(existing.orgsReporting || [existing.org]),
        ...(newActor.orgsReporting || [newActor.org])
      ])]
    };
  }

  aggregateActor(existing, newActor) {
    const merged = this.mergeActors(existing, newActor);
    merged.observationCount = (existing.observationCount || 1) + 1;
    merged.healthcareTargets = (existing.healthcareTargets || 0) + (newActor.healthcareTargets || 0);
    return merged;
  }

  mergeMalware(existing, newMalware) {
    return {
      ...existing,
      ...newMalware,
      id: existing.id, // Keep existing ID
      capabilities: [...new Set([...(existing.capabilities || []), ...(newMalware.capabilities || [])])],
      deliveryMethods: [...new Set([...(existing.deliveryMethods || []), ...(newMalware.deliveryMethods || [])])],
      associatedActors: [...new Set([...(existing.associatedActors || []), ...(newMalware.associatedActors || [])])],
      iocs: this.mergeIOCs(existing.iocs, newMalware.iocs),
      firstSeen: this.earliestDate(existing.firstSeen, newMalware.firstSeen),
      lastSeen: this.latestDate(existing.lastSeen, newMalware.lastSeen),
      orgsReporting: [...new Set([
        ...(existing.orgsReporting || [existing.org]),
        ...(newMalware.orgsReporting || [newMalware.org])
      ])]
    };
  }

  mergeIncidents(existing, newIncident) {
    return {
      ...existing,
      recordsCompromised: Math.max(existing.recordsCompromised || 0, newIncident.recordsCompromised || 0),
      financialImpact: Math.max(existing.financialImpact || 0, newIncident.financialImpact || 0),
      impactScore: Math.max(existing.impactScore || 0, newIncident.impactScore || 0),
      techniquesUsed: [...new Set([...(existing.techniquesUsed || []), ...(newIncident.techniquesUsed || [])])],
      orgsReporting: [...new Set([
        ...(existing.orgsReporting || [existing.org]),
        ...(newIncident.orgsReporting || [newIncident.org])
      ])]
    };
  }

  mergeIOCs(existing, newIOCs) {
    if (!existing) return newIOCs || {};
    if (!newIOCs) return existing || {};
    
    return {
      hashes: [...new Set([...(existing.hashes || []), ...(newIOCs.hashes || [])])],
      domains: [...new Set([...(existing.domains || []), ...(newIOCs.domains || [])])],
      ips: [...new Set([...(existing.ips || []), ...(newIOCs.ips || [])])],
      urls: [...new Set([...(existing.urls || []), ...(newIOCs.urls || [])])]
    };
  }

  getPeriod(date, periodType) {
    const d = new Date(date);
    
    if (isNaN(d)) {
      return 'unknown';
    }
    
    switch (periodType) {
      case 'daily':
        return d.toISOString().split('T')[0];
      case 'weekly':
        const week = this.getWeekNumber(d);
        return `${d.getFullYear()}-W${String(week).padStart(2, '0')}`;
      case 'monthly':
        return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      case 'quarterly':
        const quarter = Math.floor(d.getMonth() / 3) + 1;
        return `${d.getFullYear()}-Q${quarter}`;
      case 'yearly':
        return String(d.getFullYear());
      default:
        return periodType;
    }
  }

  getWeekNumber(date) {
    const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
    const dayNum = d.getUTCDay() || 7;
    d.setUTCDate(d.getUTCDate() + 4 - dayNum);
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
  }

  calculatePrevalence(items, name) {
    const count = items.filter(i => i.name === name).length;
    return items.length > 0 ? (count / items.length) * 100 : 0;
  }

  calculateVectorPrevalence(vectors, type) {
    const sameType = vectors.filter(v => v.vectorType === type);
    const totalFreq = sameType.reduce((sum, v) => sum + (v.frequency || 0), 0);
    const allFreq = vectors.reduce((sum, v) => sum + (v.frequency || 0), 1);
    return allFreq > 0 ? (totalFreq / allFreq) * 100 : 0;
  }

  compareSeverity(sev1, sev2) {
    const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
    return (severityOrder[sev1] || 0) - (severityOrder[sev2] || 0);
  }

  sortByThreatLevel(actors) {
    return actors.sort((a, b) => {
      // Sort by healthcare targets first
      if (b.healthcareTargets !== a.healthcareTargets) {
        return (b.healthcareTargets || 0) - (a.healthcareTargets || 0);
      }
      // Then by confidence
      if (b.confidence !== a.confidence) {
        return (b.confidence || 0) - (a.confidence || 0);
      }
      // Then by observation count
      return (b.observationCount || 1) - (a.observationCount || 1);
    });
  }

  earliestDate(date1, date2) {
    if (!date1) return date2;
    if (!date2) return date1;
    return new Date(date1) < new Date(date2) ? date1 : date2;
  }

  latestDate(date1, date2) {
    if (!date1) return date2;
    if (!date2) return date1;
    return new Date(date1) > new Date(date2) ? date1 : date2;
  }

  groupBy(items, keyFunc) {
    const grouped = {};
    
    for (const item of items) {
      const key = typeof keyFunc === 'function' ? keyFunc(item) : item[keyFunc];
      if (!grouped[key]) {
        grouped[key] = [];
      }
      grouped[key].push(item);
    }
    
    return grouped;
  }

  countBy(items, keyFunc) {
    const counts = {};
    
    for (const item of items) {
      const key = typeof keyFunc === 'function' ? keyFunc(item) : item[keyFunc];
      counts[key] = (counts[key] || 0) + 1;
    }
    
    return counts;
  }

  average(numbers) {
    if (!numbers || numbers.length === 0) return 0;
    return numbers.reduce((sum, n) => sum + n, 0) / numbers.length;
  }
}

module.exports = { DataAggregators };