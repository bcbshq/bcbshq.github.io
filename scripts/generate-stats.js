// scripts/generate-stats.js
const fs = require('fs-extra');
const path = require('path');

async function generateStats() {
  console.log('='.repeat(60));
  console.log('Generating Threat Intelligence Statistics');
  console.log('='.repeat(60));
  console.log('');

  try {
    const processedDir = path.join(__dirname, '../data/processed');
    
    // Load processed data
    const data = await loadProcessedData(processedDir);
    
    if (!data) {
      console.log('No processed data found. Please run ETL first.');
      return;
    }

    // Generate statistics
    const stats = {
      generated: new Date().toISOString(),
      summary: generateSummaryStats(data),
      trends: generateTrends(data),
      topThreats: generateTopThreats(data),
      coverage: generateCoverageStats(data),
      quality: generateQualityMetrics(data)
    };

    // Save statistics
    const statsPath = path.join(processedDir, 'statistics.json');
    await fs.writeJson(statsPath, stats, { spaces: 2 });
    
    // Display statistics
    displayStatistics(stats);
    
    console.log('');
    console.log(`Statistics saved to: ${statsPath}`);
    console.log('='.repeat(60));

  } catch (error) {
    console.error('Failed to generate statistics:', error);
    process.exit(1);
  }
}

async function loadProcessedData(dir) {
  const data = {};
  
  const files = [
    'threat-actors.json',
    'malware.json',
    'techniques.json',
    'incidents.json',
    'attack-vectors.json',
    'metadata.json'
  ];

  for (const file of files) {
    const filePath = path.join(dir, file);
    if (await fs.pathExists(filePath)) {
      const key = file.replace('.json', '').replace(/-/g, '_');
      data[key] = await fs.readJson(filePath);
    }
  }

  return Object.keys(data).length > 0 ? data : null;
}

function generateSummaryStats(data) {
  const summary = {
    totalRecords: 0,
    byType: {},
    reportingPeriod: null,
    orgsContributing: []
  };

  // Count records by type
  if (data.threat_actors) {
    summary.byType.threatActors = data.threat_actors.length;
    summary.totalRecords += data.threat_actors.length;
  }
  
  if (data.malware) {
    summary.byType.malware = data.malware.length;
    summary.totalRecords += data.malware.length;
  }
  
  if (data.techniques) {
    summary.byType.techniques = data.techniques.length;
    summary.totalRecords += data.techniques.length;
  }
  
  if (data.incidents) {
    // Incidents might be grouped by period
    if (Array.isArray(data.incidents) && data.incidents[0]?.incidents) {
      summary.byType.incidents = data.incidents.reduce((sum, period) => 
        sum + (period.incidents?.length || 0), 0);
    } else {
      summary.byType.incidents = data.incidents.length;
    }
    summary.totalRecords += summary.byType.incidents;
  }
  
  if (data.attack_vectors) {
    summary.byType.attackVectors = data.attack_vectors.length;
    summary.totalRecords += data.attack_vectors.length;
  }

  // Get metadata
  if (data.metadata) {
    summary.reportingPeriod = data.metadata.period;
    summary.orgsContributing = data.metadata.orgs;
    summary.processedDate = data.metadata.processedDate;
  }

  return summary;
}

function generateTrends(data) {
  const trends = {
    mostActiveActors: [],
    emergingThreats: [],
    increasingTechniques: [],
    targetedSectors: {}
  };

  // Most active threat actors
  if (data.threat_actors) {
    trends.mostActiveActors = data.threat_actors
      .filter(a => a.healthcareTargets > 0)
      .sort((a, b) => (b.healthcareTargets || 0) - (a.healthcareTargets || 0))
      .slice(0, 10)
      .map(a => ({
        name: a.name,
        type: a.type,
        targets: a.healthcareTargets,
        confidence: a.confidence
      }));
  }

  // Emerging threats (recently seen)
  if (data.threat_actors) {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    trends.emergingThreats = data.threat_actors
      .filter(a => new Date(a.lastSeen || a.lastUpdated) > thirtyDaysAgo)
      .map(a => ({
        name: a.name,
        type: a.type,
        firstSeen: a.firstSeen,
        lastSeen: a.lastSeen || a.lastUpdated
      }))
      .slice(0, 5);
  }

  // Most observed techniques
  if (data.techniques) {
    trends.increasingTechniques = data.techniques
      .sort((a, b) => (b.aggregatedFrequency || 0) - (a.aggregatedFrequency || 0))
      .slice(0, 10)
      .map(t => ({
        id: t.techniqueId,
        name: t.name,
        frequency: t.aggregatedFrequency,
        severity: t.severity || t.averageSeverity,
        tactics: Array.isArray(t.tactic) ? t.tactic : [t.tactic]
      }));
  }

  // Targeted sectors from incidents
  if (data.incidents) {
    if (Array.isArray(data.incidents) && data.incidents[0]?.statistics) {
      // Aggregated format
      data.incidents.forEach(period => {
        if (period.statistics?.bySector) {
          Object.entries(period.statistics.bySector).forEach(([sector, count]) => {
            trends.targetedSectors[sector] = (trends.targetedSectors[sector] || 0) + count;
          });
        }
      });
    } else {
      // Direct format
      data.incidents.forEach(incident => {
        const sector = incident.sector || 'unknown';
        trends.targetedSectors[sector] = (trends.targetedSectors[sector] || 0) + 1;
      });
    }
  }

  return trends;
}

function generateTopThreats(data) {
  const threats = {
    criticalActors: [],
    criticalMalware: [],
    criticalIncidents: [],
    highRiskVectors: []
  };

  // Critical actors (high confidence + high activity)
  if (data.threat_actors) {
    threats.criticalActors = data.threat_actors
      .filter(a => a.confidence >= 70 && a.healthcareTargets > 0)
      .sort((a, b) => {
        const scoreA = (a.confidence / 100) * a.healthcareTargets;
        const scoreB = (b.confidence / 100) * b.healthcareTargets;
        return scoreB - scoreA;
      })
      .slice(0, 5)
      .map(a => ({
        name: a.name,
        type: a.type,
        score: Math.round((a.confidence / 100) * a.healthcareTargets),
        targets: a.healthcareTargets,
        ttps: a.ttps?.length || 0
      }));
  }

  // Critical malware
  if (data.malware) {
    threats.criticalMalware = data.malware
      .filter(m => m.impact === 'critical' || m.impact === 'high')
      .slice(0, 5)
      .map(m => ({
        name: m.name,
        family: m.family,
        type: m.type,
        impact: m.impact,
        actors: m.associatedActors?.length || 0
      }));
  }

  // Critical incidents
  if (data.incidents) {
    let allIncidents = [];
    
    if (Array.isArray(data.incidents) && data.incidents[0]?.incidents) {
      // Aggregated format
      data.incidents.forEach(period => {
        allIncidents = allIncidents.concat(period.incidents || []);
      });
    } else {
      allIncidents = data.incidents;
    }
    
    threats.criticalIncidents = allIncidents
      .filter(i => i.impactScore >= 70 || i.patientCareImpact === 'critical')
      .sort((a, b) => (b.impactScore || 0) - (a.impactScore || 0))
      .slice(0, 5)
      .map(i => ({
        id: i.id,
        organization: i.organization || 'Undisclosed',
        date: i.incidentDate,
        type: i.attackType,
        impactScore: i.impactScore,
        patientImpact: i.patientCareImpact
      }));
  }

  // High risk vectors
  if (data.attack_vectors) {
    threats.highRiskVectors = data.attack_vectors
      .filter(v => v.riskScore >= 60)
      .sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0))
      .slice(0, 5)
      .map(v => ({
        type: v.vectorType,
        riskScore: v.riskScore,
        severity: v.severity,
        frequency: v.aggregatedFrequency || v.frequency,
        actors: v.actorsUsing?.length || 0
      }));
  }

  return threats;
}

function generateCoverageStats(data) {
  const coverage = {
    dataCompleteness: {},
    orgContribution: {},
    temporalCoverage: {},
    geographicCoverage: {}
  };

  // Data completeness
  const checkCompleteness = (records, requiredFields) => {
    if (!records || records.length === 0) return 0;
    
    let totalFields = 0;
    let completedFields = 0;
    
    records.forEach(record => {
      requiredFields.forEach(field => {
        totalFields++;
        if (record[field] !== undefined && record[field] !== null && record[field] !== '') {
          completedFields++;
        }
      });
    });
    
    return totalFields > 0 ? Math.round((completedFields / totalFields) * 100) : 0;
  };

  if (data.threat_actors) {
    coverage.dataCompleteness.threatActors = checkCompleteness(
      data.threat_actors,
      ['name', 'type', 'motivation', 'ttps', 'confidence']
    );
  }

  if (data.malware) {
    coverage.dataCompleteness.malware = checkCompleteness(
      data.malware,
      ['name', 'type', 'family', 'capabilities', 'impact']
    );
  }

  // Org contribution
  const countByOrg = (records) => {
    const counts = {};
    records.forEach(record => {
      if (record.orgsReporting) {
        record.orgsReporting.forEach(sub => {
          counts[sub] = (counts[sub] || 0) + 1;
        });
      } else if (record.org) {
        counts[record.org] = (counts[record.org] || 0) + 1;
      }
    });
    return counts;
  };

  if (data.threat_actors) {
    const actorCounts = countByOrg(data.threat_actors);
    Object.entries(actorCounts).forEach(([sub, count]) => {
      if (!coverage.orgContribution[sub]) {
        coverage.orgContribution[sub] = {};
      }
      coverage.orgContribution[sub].threatActors = count;
    });
  }

  // Temporal coverage
  const getDateRange = (records, dateField) => {
    const dates = records
      .map(r => r[dateField])
      .filter(d => d)
      .map(d => new Date(d));
    
    if (dates.length === 0) return null;
    
    const minDate = new Date(Math.min(...dates));
    const maxDate = new Date(Math.max(...dates));
    
    return {
      earliest: minDate.toISOString().split('T')[0],
      latest: maxDate.toISOString().split('T')[0],
      spanDays: Math.round((maxDate - minDate) / (1000 * 60 * 60 * 24))
    };
  };

  if (data.threat_actors) {
    coverage.temporalCoverage.threatActors = getDateRange(data.threat_actors, 'lastSeen');
  }

  if (data.incidents) {
    let allIncidents = [];
    if (Array.isArray(data.incidents) && data.incidents[0]?.incidents) {
      data.incidents.forEach(period => {
        allIncidents = allIncidents.concat(period.incidents || []);
      });
    } else {
      allIncidents = data.incidents;
    }
    coverage.temporalCoverage.incidents = getDateRange(allIncidents, 'incidentDate');
  }

  return coverage;
}

function generateQualityMetrics(data) {
  const quality = {
    confidenceScores: {},
    dataFreshness: {},
    correlationStrength: {}
  };

  // Average confidence scores
  if (data.threat_actors) {
    const confidences = data.threat_actors
      .map(a => a.confidence)
      .filter(c => c !== undefined);
    
    if (confidences.length > 0) {
      quality.confidenceScores.threatActors = {
        average: Math.round(confidences.reduce((a, b) => a + b, 0) / confidences.length),
        min: Math.min(...confidences),
        max: Math.max(...confidences),
        high: confidences.filter(c => c >= 80).length,
        medium: confidences.filter(c => c >= 50 && c < 80).length,
        low: confidences.filter(c => c < 50).length
      };
    }
  }

  // Data freshness
  const calculateFreshness = (records, dateField) => {
    const now = new Date();
    const ages = records
      .map(r => r[dateField])
      .filter(d => d)
      .map(d => {
        const date = new Date(d);
        return Math.round((now - date) / (1000 * 60 * 60 * 24)); // Days old
      });
    
    if (ages.length === 0) return null;
    
    return {
      averageAgeDays: Math.round(ages.reduce((a, b) => a + b, 0) / ages.length),
      newestAgeDays: Math.min(...ages),
      oldestAgeDays: Math.max(...ages),
      under7Days: ages.filter(a => a < 7).length,
      under30Days: ages.filter(a => a < 30).length,
      over30Days: ages.filter(a => a >= 30).length
    };
  };

  if (data.threat_actors) {
    quality.dataFreshness.threatActors = calculateFreshness(data.threat_actors, 'lastUpdated');
  }

  // Correlation strength (how well data is connected)
  if (data.threat_actors && data.malware) {
    const actorsWithMalware = data.threat_actors.filter(a => 
      a.malwareUsed && a.malwareUsed.length > 0
    ).length;
    
    quality.correlationStrength.actorMalware = {
      actorsWithMalware,
      totalActors: data.threat_actors.length,
      percentage: Math.round((actorsWithMalware / data.threat_actors.length) * 100)
    };
  }

  if (data.threat_actors && data.techniques) {
    const actorsWithTTPs = data.threat_actors.filter(a => 
      a.ttps && a.ttps.length > 0
    ).length;
    
    quality.correlationStrength.actorTechniques = {
      actorsWithTTPs,
      totalActors: data.threat_actors.length,
      percentage: Math.round((actorsWithTTPs / data.threat_actors.length) * 100)
    };
  }

  return quality;
}

function displayStatistics(stats) {
  console.log('Summary Statistics:');
  console.log('-'.repeat(40));
  console.log(`Total Records: ${stats.summary.totalRecords}`);
  console.log(`Reporting Period: ${stats.summary.reportingPeriod || 'N/A'}`);
  console.log(`Orgs: ${stats.summary.orgsContributing?.join(', ') || 'N/A'}`);
  console.log('');

  console.log('Record Breakdown:');
  Object.entries(stats.summary.byType).forEach(([type, count]) => {
    console.log(`  ${type}: ${count}`);
  });
  console.log('');

  console.log('Top Threats:');
  console.log('-'.repeat(40));
  
  if (stats.topThreats.criticalActors.length > 0) {
    console.log('Critical Actors:');
    stats.topThreats.criticalActors.forEach(actor => {
      console.log(`  - ${actor.name} (${actor.type}): ${actor.targets} targets`);
    });
  }
  
  if (stats.topThreats.highRiskVectors.length > 0) {
    console.log('\nHigh Risk Vectors:');
    stats.topThreats.highRiskVectors.forEach(vector => {
      console.log(`  - ${vector.type}: Risk Score ${vector.riskScore}`);
    });
  }
  console.log('');

  console.log('Data Quality:');
  console.log('-'.repeat(40));
  
  if (stats.quality.confidenceScores.threatActors) {
    const conf = stats.quality.confidenceScores.threatActors;
    console.log(`Threat Actor Confidence: ${conf.average}% average`);
    console.log(`  High: ${conf.high}, Medium: ${conf.medium}, Low: ${conf.low}`);
  }
  
  if (stats.quality.dataFreshness.threatActors) {
    const fresh = stats.quality.dataFreshness.threatActors;
    console.log(`\nData Freshness (Threat Actors):`);
    console.log(`  Average age: ${fresh.averageAgeDays} days`);
    console.log(`  Under 7 days: ${fresh.under7Days}, Under 30 days: ${fresh.under30Days}`);
  }
  
  if (stats.quality.correlationStrength.actorMalware) {
    const corr = stats.quality.correlationStrength.actorMalware;
    console.log(`\nActor-Malware Correlation: ${corr.percentage}%`);
  }
}

// Run statistics generation
generateStats();