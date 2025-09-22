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
      aggregationPeriod: config.aggregationPeriod || 'monthly',
      validateWithBaseSchema: config.validateWithBaseSchema !== false // Default true
    };
    
    this.validators = new DataValidators();
    this.transformers = new DataTransformers();
    this.aggregators = new DataAggregators();
    
    // Track validation statistics
    this.validationStats = {
      totalFiles: 0,
      validFiles: 0,
      invalidFiles: 0,
      warnings: [],
      errors: []
    };
  }

  async processIncomingData() {
    console.log('Starting ETL process...');
    console.log('Processing Orgs:', this.config.orgs);
    console.log('Base Schema Validation:', this.config.validateWithBaseSchema ? 'Enabled' : 'Disabled');
    
    try {
      // 1. Extract
      const rawData = await this.extractData();
      console.log('Extracted data:', this.summarizeData(rawData));
      
      // 2. Validate
      const validatedData = await this.validateData(rawData);
      console.log('Validated data:', this.summarizeData(validatedData));
      
      // Display validation statistics
      this.displayValidationStats();
      
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

    // Load base schema if validation is enabled
    if (this.config.validateWithBaseSchema) {
      await this.validators.loadBaseSchema();
    }

    for (const subsidiary of this.config.orgs) {
      const subsidiaryPath = path.join(this.config.inputDirectory, subsidiary);
      
      // Check if subsidiary directory exists
      if (!await fs.pathExists(subsidiaryPath)) {
        console.warn(`Subsidiary directory not found: ${subsidiaryPath}`);
        continue;
      }
      
      // Read JSON files from subsidiary directory
      const files = await fs.readdir(subsidiaryPath);
      
      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        
        const filePath = path.join(subsidiaryPath, file);
        this.validationStats.totalFiles++;
        
        try {
          const content = await fs.readJson(filePath);
          
          // Validate submission structure if base schema validation is enabled
          if (this.config.validateWithBaseSchema) {
            const structureValidation = await this.validators.validateSubmissionStructure(content);
            
            if (!structureValidation.valid) {
              console.error(`Invalid submission structure in ${filePath}:`);
              structureValidation.errors.forEach(e => console.error(`  - ${e}`));
              this.validationStats.invalidFiles++;
              this.validationStats.errors.push({
                file: `${subsidiary}/${file}`,
                errors: structureValidation.errors
              });
              continue; // Skip this file
            }
          }
          
          this.validationStats.validFiles++;
          
          // Add subsidiary info to each record
          if (content.data && Array.isArray(content.data)) {
            content.data = content.data.map(record => ({
              ...record,
              subsidiary: subsidiary,
              sourceFile: file,
              extractedAt: new Date().toISOString(),
              schemaVersion: content.metadata?.version || '1.0'
            }));
          }
          
          // Check for record count mismatch
          if (content.metadata?.recordCount !== undefined && 
              content.data && 
              content.metadata.recordCount !== content.data.length) {
            this.validationStats.warnings.push({
              file: `${subsidiary}/${file}`,
              warning: `Record count mismatch: declared ${content.metadata.recordCount}, actual ${content.data.length}`
            });
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
              this.validationStats.warnings.push({
                file: `${subsidiary}/${file}`,
                warning: `Unknown data type: ${content.dataType}`
              });
          }
        } catch (error) {
          console.error(`Error processing ${filePath}:`, error.message);
          this.validationStats.invalidFiles++;
          this.validationStats.errors.push({
            file: `${subsidiary}/${file}`,
            errors: [error.message]
          });
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
        console.warn(`Invalid threat actor from ${actor.subsidiary}:`, validation.errors);
      }
    }

    for (const malware of data.malware) {
      const validation = this.validators.validateRecord(malware, schemas.malware);
      if (validation.valid) {
        validated.malware.push(validation.data);
      } else {
        console.warn(`Invalid malware from ${malware.subsidiary}:`, validation.errors);
      }
    }

    for (const technique of data.techniques) {
      const validation = this.validators.validateRecord(technique, schemas.technique);
      if (validation.valid) {
        // Additional MITRE ATT&CK validation
        if (technique.techniqueId && !this.validators.validateTechniqueId(technique.techniqueId)) {
          console.warn(`Invalid MITRE technique ID: ${technique.techniqueId}`);
        }
        validated.techniques.push(validation.data);
      } else {
        console.warn(`Invalid technique from ${technique.subsidiary}:`, validation.errors);
      }
    }

    for (const incident of data.incidents) {
      const validation = this.validators.validateRecord(incident, schemas.incident);
      if (validation.valid) {
        // Additional date range validation for incidents
        if (incident.incidentDate && incident.resolutionDate) {
          const dateValidation = this.validators.validateDateRange(
            incident.incidentDate, 
            incident.resolutionDate
          );
          if (!dateValidation.valid) {
            console.warn(`Invalid date range in incident ${incident.id}: ${dateValidation.error}`);
          }
        }
        validated.incidents.push(validation.data);
      } else {
        console.warn(`Invalid incident from ${incident.subsidiary}:`, validation.errors);
      }
    }

    for (const vector of data.attackVectors) {
      const validation = this.validators.validateRecord(vector, schemas.attackVector);
      if (validation.valid) {
        // Additional CVE validation if present
        if (vector.exploitedVulnerabilities) {
          vector.exploitedVulnerabilities.forEach(vuln => {
            if (vuln.cve && !this.validators.validateCVE(vuln.cve)) {
              console.warn(`Invalid CVE format: ${vuln.cve}`);
            }
          });
        }
        validated.attackVectors.push(validation.data);
      } else {
        console.warn(`Invalid attack vector from ${vector.subsidiary}:`, validation.errors);
      }
    }

    return validated;
  }

  async loadSchemas() {
    const schemas = {};
    const schemaDir = path.join(__dirname, '../../data/schemas');
    
    // Ensure schema directory exists
    await fs.ensureDir(schemaDir);
    
    const schemaFiles = {
      base: 'base-submission-schema.json',
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
        console.log(`Loaded schema: ${file}`);
      } else {
        console.warn(`Schema file not found: ${schemaPath}`);
        schemas[key] = { fields: {} }; // Empty schema as fallback
      }
    }

    return schemas;
  }

  async transformData(data) {
    // Sanitize all data before transformation
    const sanitized = {
      threatActors: this.validators.sanitizeData(data.threatActors),
      malware: this.validators.sanitizeData(data.malware),
      techniques: this.validators.sanitizeData(data.techniques),
      incidents: this.validators.sanitizeData(data.incidents),
      attackVectors: this.validators.sanitizeData(data.attackVectors)
    };

    return {
      threatActors: this.transformers.normalizeActors(sanitized.threatActors),
      malware: this.transformers.normalizeMalware(sanitized.malware),
      techniques: this.transformers.normalizeTechniques(sanitized.techniques),
      incidents: this.transformers.normalizeIncidents(sanitized.incidents),
      attackVectors: this.transformers.normalizeVectors(sanitized.attackVectors)
    };
  }

  async deduplicateData(data) {
    const strategy = this.config.deduplicationStrategy;
    
    console.log(`Deduplication strategy: ${strategy}`);
    
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
    
    console.log(`Aggregation period: ${period}`);
    
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
        deduplicationStrategy: this.config.deduplicationStrategy,
        schemaValidation: this.config.validateWithBaseSchema,
        validationStats: this.validationStats,
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
    
    // Save validation report if there were issues
    if (this.validationStats.errors.length > 0 || this.validationStats.warnings.length > 0) {
      const validationReportPath = path.join(this.config.outputDirectory, 'validation-report.json');
      await fs.writeJson(validationReportPath, this.validationStats, { spaces: 2 });
      console.log('Saved validation-report.json');
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
    for (const subsidiary of this.config.orgs) {
      const subsidiaryPath = path.join(this.config.inputDirectory, subsidiary);
      
      if (!await fs.pathExists(subsidiaryPath)) continue;
      
      const files = await fs.readdir(subsidiaryPath);
      
      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        
        const source = path.join(subsidiaryPath, file);
        const dest = path.join(archivePath, `${subsidiary}-${file}`);
        
        try {
          await fs.move(source, dest, { overwrite: true });
          console.log(`Archived ${subsidiary}/${file}`);
        } catch (error) {
          console.error(`Failed to archive ${source}:`, error.message);
        }
      }
    }
  }

  displayValidationStats() {
    console.log('\nValidation Statistics:');
    console.log('-'.repeat(40));
    console.log(`Total files processed: ${this.validationStats.totalFiles}`);
    console.log(`Valid files: ${this.validationStats.validFiles}`);
    console.log(`Invalid files: ${this.validationStats.invalidFiles}`);
    
    if (this.validationStats.warnings.length > 0) {
      console.log(`\nWarnings (${this.validationStats.warnings.length}):`);
      this.validationStats.warnings.forEach(w => {
        console.log(`  [${w.file}] ${w.warning}`);
      });
    }
    
    if (this.validationStats.errors.length > 0) {
      console.log(`\nErrors (${this.validationStats.errors.length}):`);
      this.validationStats.errors.forEach(e => {
        console.log(`  [${e.file}]`);
        e.errors.forEach(err => console.log(`    - ${err}`));
      });
    }
    console.log('-'.repeat(40));
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