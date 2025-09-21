// modules/core/etl.js
const fs = require('fs-extra');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { DataValidators } = require('./validators');
const { DataTransformers } = require('./transformers');
const { DataAggregators } = require('./aggregators');

class ThreatIntelETL {
  constructor(config) {
    this.config = {
      inputDirectory: config.inputDirectory || './data/input',
      outputDirectory: config.outputDirectory || './data/processed',
      archiveDirectory: config.archiveDirectory || './data/archive',
      orgs: config.orgs || [],
      deduplicationStrategy: config.deduplicationStrategy || 'merge',
      aggregationPeriod: config.aggregationPeriod || 'monthly'
    };
    
    this.validators = new DataValidators();
    this.transformers = new DataTransformers();
    this.aggregators = new DataAggregators();
  }

  async processIncomingData() {
    console.log('Starting ETL process...');
    console.log('Processing Orgs:', this.config.orgs);
    
    try {
      // 1. Extract
      const rawData = await this.extractData();
      console.log('Extracted data:', this.summarizeData(rawData));
      
      // 2. Validate
      const validatedData = await this.validateData(rawData);
      console.log('Validated data:', this.summarizeData(validatedData));
      
      // 3. Transform
      const transformedData = await this.transformData(validatedData);
      console.log('Transformed data:', this.summarizeData(transformedData));
      
      // 4. Deduplicate
      const dedupedData = await this.deduplicateData(transformedData);
      console.log('Deduplicated data:', this.summarizeData(dedupedData));
      
      // 5. Aggregate
      const aggregatedData = await this.aggregateData(dedupedData);
      console.log('Aggregated data:', this.summarizeData(aggregatedData));
      
      // 6. Load
      await this.loadData(aggregatedData);
      
      // 7. Archive processed files
      await this.archiveProcessedFiles();
      
      console.log('ETL process complete');
      return aggregatedData;
    } catch (error) {
      console.error('ETL process failed:', error);
      throw error;
    }
  }

  async extractData() {
    const data = {
      threatActors: [],
      malware: [],
      techniques: [],
      incidents: [],
      attackVectors: []
    };

    for (const org of this.config.orgs) {
      const orgPath = path.join(this.config.inputDirectory, org);
      
      // Check if org directory exists
      if (!await fs.pathExists(orgPath)) {
        console.warn(`org directory not found: ${orgPath}`);
        continue;
      }
      
      // Read JSON files from org directory
      const files = await fs.readdir(orgPath);
      
      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        
        const filePath = path.join(orgPath, file);
        
        try {
          const content = await fs.readJson(filePath);
          
          // Add org info to each record
          if (content.data && Array.isArray(content.data)) {
            content.data = content.data.map(record => ({
              ...record,
              org: org,
              sourceFile: file,
              extractedAt: new Date().toISOString()
            }));
          }
          
          // Categorize by data type
          switch (content.dataType) {
            case 'threatActor':
              data.threatActors.push(...this.ensureArray(content.data));
              break;
            case 'malware':
              data.malware.push(...this.ensureArray(content.data));
              break;
            case 'technique':
              data.techniques.push(...this.ensureArray(content.data));
              break;
            case 'incident':
              data.incidents.push(...this.ensureArray(content.data));
              break;
            case 'attackVector':
              data.attackVectors.push(...this.ensureArray(content.data));
              break;
            default:
              console.warn(`Unknown data type in ${filePath}: ${content.dataType}`);
          }
        } catch (error) {
          console.error(`Error processing ${filePath}:`, error.message);
        }
      }
    }

    return data;
  }

  async validateData(data) {
    const validated = {
      threatActors: [],
      malware: [],
      techniques: [],
      incidents: [],
      attackVectors: []
    };

    // Load schemas
    const schemas = await this.loadSchemas();

    // Validate each data type
    for (const actor of data.threatActors) {
      const validation = this.validators.validateRecord(actor, schemas.threatActor);
      if (validation.valid) {
        validated.threatActors.push(validation.data);
      } else {
        console.warn(`Invalid threat actor from ${actor.org}:`, validation.errors);
      }
    }

    for (const malware of data.malware) {
      const validation = this.validators.validateRecord(malware, schemas.malware);
      if (validation.valid) {
        validated.malware.push(validation.data);
      } else {
        console.warn(`Invalid malware from ${malware.org}:`, validation.errors);
      }
    }

    for (const technique of data.techniques) {
      const validation = this.validators.validateRecord(technique, schemas.technique);
      if (validation.valid) {
        validated.techniques.push(validation.data);
      } else {
        console.warn(`Invalid technique from ${technique.org}:`, validation.errors);
      }
    }

    for (const incident of data.incidents) {
      const validation = this.validators.validateRecord(incident, schemas.incident);
      if (validation.valid) {
        validated.incidents.push(validation.data);
      } else {
        console.warn(`Invalid incident from ${incident.org}:`, validation.errors);
      }
    }

    for (const vector of data.attackVectors) {
      const validation = this.validators.validateRecord(vector, schemas.attackVector);
      if (validation.valid) {
        validated.attackVectors.push(validation.data);
      } else {
        console.warn(`Invalid attack vector from ${vector.org}:`, validation.errors);
      }
    }

    return validated;
  }

  async loadSchemas() {
    const schemas = {};
    const schemaDir = path.join(__dirname, '../../data/schemas');
    
    const schemaFiles = {
      threatActor: 'threat-actor-schema.json',
      malware: 'malware-schema.json',
      technique: 'technique-schema.json',
      incident: 'incident-schema.json',
      attackVector: 'attack-vector-schema.json'
    };

    for (const [key, file] of Object.entries(schemaFiles)) {
      const schemaPath = path.join(schemaDir, file);
      if (await fs.pathExists(schemaPath)) {
        schemas[key] = await fs.readJson(schemaPath);
      } else {
        console.warn(`Schema file not found: ${schemaPath}`);
        schemas[key] = { fields: {} }; // Empty schema as fallback
      }
    }

    return schemas;
  }

  async transformData(data) {
    return {
      threatActors: this.transformers.normalizeActors(data.threatActors),
      malware: this.transformers.normalizeMalware(data.malware),
      techniques: this.transformers.normalizeTechniques(data.techniques),
      incidents: this.transformers.normalizeIncidents(data.incidents),
      attackVectors: this.transformers.normalizeVectors(data.attackVectors)
    };
  }

  async deduplicateData(data) {
    const strategy = this.config.deduplicationStrategy;
    
    return {
      threatActors: this.aggregators.deduplicateActors(data.threatActors, strategy),
      malware: this.aggregators.deduplicateMalware(data.malware, strategy),
      techniques: this.aggregators.deduplicateTechniques(data.techniques, strategy),
      incidents: this.aggregators.deduplicateIncidents(data.incidents, strategy),
      attackVectors: this.aggregators.deduplicateVectors(data.attackVectors, strategy)
    };
  }

  async aggregateData(data) {
    const period = this.config.aggregationPeriod;
    
    return {
      threatActors: this.aggregators.aggregateActors(data.threatActors, period),
      malware: this.aggregators.aggregateMalware(data.malware, period),
      techniques: this.aggregators.aggregateTechniques(data.techniques, period),
      incidents: this.aggregators.aggregateIncidents(data.incidents, period),
      attackVectors: this.aggregators.aggregateVectors(data.attackVectors, period),
      mappings: this.aggregators.generateMappings(data),
      metadata: {
        processedDate: new Date().toISOString(),
        period: period,
        orgs: this.config.orgs,
        recordCounts: {
          threatActors: data.threatActors.length,
          malware: data.malware.length,
          techniques: data.techniques.length,
          incidents: data.incidents.length,
          attackVectors: data.attackVectors.length
        }
      }
    };
  }

  async loadData(data) {
    // Ensure output directory exists
    await fs.ensureDir(this.config.outputDirectory);

    // Save each data type to its own file
    const files = [
      { name: 'threat-actors.json', data: data.threatActors },
      { name: 'malware.json', data: data.malware },
      { name: 'techniques.json', data: data.techniques },
      { name: 'incidents.json', data: data.incidents },
      { name: 'attack-vectors.json', data: data.attackVectors },
      { name: 'mappings.json', data: data.mappings },
      { name: 'metadata.json', data: data.metadata }
    ];

    for (const file of files) {
      const outputPath = path.join(this.config.outputDirectory, file.name);
      await fs.writeJson(outputPath, file.data, { spaces: 2 });
      console.log(`Saved ${file.name} (${Array.isArray(file.data) ? file.data.length : 1} records)`);
    }
  }

  async archiveProcessedFiles() {
    const now = new Date();
    const archivePath = path.join(
      this.config.archiveDirectory,
      now.getFullYear().toString(),
      (now.getMonth() + 1).toString().padStart(2, '0')
    );

    await fs.ensureDir(archivePath);

    // Move processed input files to archive
    for (const org of this.config.orgs) {
      const orgPath = path.join(this.config.inputDirectory, org);
      
      if (!await fs.pathExists(orgPath)) continue;
      
      const files = await fs.readdir(orgPath);
      
      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        
        const source = path.join(orgPath, file);
        const dest = path.join(archivePath, `${org}-${file}`);
        
        try {
          await fs.move(source, dest, { overwrite: true });
          console.log(`Archived ${org}/${file}`);
        } catch (error) {
          console.error(`Failed to archive ${source}:`, error.message);
        }
      }
    }
  }

  // Helper methods
  ensureArray(data) {
    return Array.isArray(data) ? data : [data].filter(Boolean);
  }

  summarizeData(data) {
    return Object.entries(data).reduce((summary, [key, value]) => {
      summary[key] = Array.isArray(value) ? value.length : 1;
      return summary;
    }, {});
  }
}

module.exports = { ThreatIntelETL };