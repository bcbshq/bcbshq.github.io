// modules/core/schema-loader.js
const fs = require('fs-extra');
const path = require('path');

/**
 * Schema Loader - Handles loading and caching of all validation schemas
 */
class SchemaLoader {
  constructor() {
    this.schemas = {};
    this.loaded = false;
    this.schemaDir = path.join(__dirname, '../../data/schemas');
    
    // Define schema file mappings
    this.schemaFiles = {
      base: 'base-submission-schema.json',
      threatActor: 'threat-actor-schema.json',
      malware: 'malware-schema.json',
      technique: 'technique-schema.json',
      incident: 'incident-schema.json',
      attackVector: 'attack-vector-schema.json'
    };
    
    // Map dataType values to schema keys
    this.dataTypeMapping = {
      'threatActor': 'threatActor',
      'malware': 'malware',
      'technique': 'technique',
      'incident': 'incident',
      'attackVector': 'attackVector'
    };
  }

  /**
   * Load all schemas into memory
   */
  async loadAllSchemas() {
    if (this.loaded) {
      return this.schemas;
    }

    console.log('Loading validation schemas...');
    
    // Ensure schema directory exists
    await fs.ensureDir(this.schemaDir);
    
    const loadPromises = [];
    
    for (const [key, filename] of Object.entries(this.schemaFiles)) {
      loadPromises.push(this.loadSchema(key, filename));
    }
    
    await Promise.all(loadPromises);
    
    this.loaded = true;
    console.log(`Loaded ${Object.keys(this.schemas).length} schemas`);
    
    return this.schemas;
  }

  /**
   * Load a single schema
   */
  async loadSchema(key, filename) {
    const schemaPath = path.join(this.schemaDir, filename);
    
    try {
      if (await fs.pathExists(schemaPath)) {
        const schema = await fs.readJson(schemaPath);
        this.schemas[key] = schema;
        console.log(`  ✓ Loaded ${filename}`);
        return schema;
      } else {
        console.warn(`  ✗ Schema not found: ${filename}`);
        // Create a minimal fallback schema
        this.schemas[key] = this.createFallbackSchema(key);
        return this.schemas[key];
      }
    } catch (error) {
      console.error(`  ✗ Failed to load ${filename}:`, error.message);
      this.schemas[key] = this.createFallbackSchema(key);
      return this.schemas[key];
    }
  }

  /**
   * Get a specific schema
   */
  async getSchema(key) {
    if (!this.loaded) {
      await this.loadAllSchemas();
    }
    
    return this.schemas[key];
  }

  /**
   * Get schema for a specific data type
   */
  async getSchemaForDataType(dataType) {
    const schemaKey = this.dataTypeMapping[dataType];
    
    if (!schemaKey) {
      console.warn(`Unknown dataType: ${dataType}`);
      return null;
    }
    
    return await this.getSchema(schemaKey);
  }

  /**
   * Get the base submission schema
   */
  async getBaseSchema() {
    return await this.getSchema('base');
  }

  /**
   * Create a fallback schema when the actual schema file is missing
   */
  createFallbackSchema(key) {
    // Base fallback structure
    const fallback = {
      "$schema": "http://json-schema.org/draft-07/schema#",
      "title": `Fallback ${key} Schema`,
      "description": "Minimal fallback schema - actual schema file not found",
      "type": "object"
    };
    
    // Add specific requirements based on schema type
    switch (key) {
      case 'base':
        fallback.required = ['metadata', 'dataType', 'data'];
        fallback.properties = {
          metadata: {
            type: 'object',
            required: ['version', 'org', 'submissionDate']
          },
          dataType: {
            type: 'string',
            enum: ['threatActor', 'malware', 'technique', 'incident', 'attackVector']
          },
          data: {
            type: 'array',
            minItems: 1
          }
        };
        break;
        
      case 'threatActor':
        fallback.fields = {
          name: { required: true, type: 'string' },
          type: { required: true, type: 'string' },
          org: { required: true, type: 'string' },
          telemetryDate: { required: true, type: 'date' }
        };
        break;
        
      case 'malware':
        fallback.fields = {
          name: { required: true, type: 'string' },
          type: { required: true, type: 'string' },
          org: { required: true, type: 'string' },
          telemetryDate: { required: true, type: 'date' }
        };
        break;
        
      case 'technique':
        fallback.fields = {
          techniqueId: { required: true, type: 'string', pattern: '^T\\d{4}(\\.\\d{3})?$' },
          name: { required: true, type: 'string' },
          tactic: { required: true, type: 'array' },
          org: { required: true, type: 'string' },
          telemetryDate: { required: true, type: 'date' }
        };
        break;
        
      case 'incident':
        fallback.fields = {
          id: { required: true, type: 'string' },
          sector: { required: true, type: 'string' },
          attackType: { required: true, type: 'string' },
          org: { required: true, type: 'string' },
          telemetryDate: { required: true, type: 'date' }
        };
        break;
        
      case 'attackVector':
        fallback.fields = {
          vectorType: { required: true, type: 'string' },
          frequency: { required: true, type: 'number' },
          severity: { required: true, type: 'string' },
          org: { required: true, type: 'string' },
          telemetryDate: { required: true, type: 'date' }
        };
        break;
        
      default:
        fallback.fields = {};
    }
    
    return fallback;
  }

  /**
   * Validate that all required schemas are present
   */
  async validateSchemaPresence() {
    const missing = [];
    const present = [];
    
    for (const [key, filename] of Object.entries(this.schemaFiles)) {
      const schemaPath = path.join(this.schemaDir, filename);
      if (await fs.pathExists(schemaPath)) {
        present.push(filename);
      } else {
        missing.push(filename);
      }
    }
    
    return {
      present,
      missing,
      complete: missing.length === 0,
      summary: `${present.length}/${Object.keys(this.schemaFiles).length} schemas present`
    };
  }

  /**
   * Get schema version from a submission
   */
  extractSchemaVersion(submission) {
    return submission?.metadata?.version || '1.0';
  }

  /**
   * Check if a schema version is supported
   */
  isVersionSupported(version) {
    // Currently support 1.0 and 1.1
    const supportedVersions = ['1.0', '1.1'];
    return supportedVersions.includes(version);
  }

  /**
   * Get all available data types
   */
  getAvailableDataTypes() {
    return Object.keys(this.dataTypeMapping);
  }

  /**
   * Clear the schema cache
   */
  clearCache() {
    this.schemas = {};
    this.loaded = false;
    console.log('Schema cache cleared');
  }

  /**
   * Reload all schemas (useful for development)
   */
  async reloadSchemas() {
    this.clearCache();
    return await this.loadAllSchemas();
  }

  /**
   * Export schemas for documentation or external validation
   */
  async exportSchemas(outputDir) {
    if (!this.loaded) {
      await this.loadAllSchemas();
    }
    
    await fs.ensureDir(outputDir);
    
    for (const [key, schema] of Object.entries(this.schemas)) {
      const filename = `${key}-schema-export.json`;
      const outputPath = path.join(outputDir, filename);
      await fs.writeJson(outputPath, schema, { spaces: 2 });
      console.log(`Exported ${filename}`);
    }
    
    // Create a combined schema document
    const combined = {
      generated: new Date().toISOString(),
      schemas: this.schemas,
      dataTypes: this.getAvailableDataTypes(),
      files: this.schemaFiles
    };
    
    const combinedPath = path.join(outputDir, 'all-schemas.json');
    await fs.writeJson(combinedPath, combined, { spaces: 2 });
    console.log('Exported all-schemas.json');
    
    return {
      exportedCount: Object.keys(this.schemas).length,
      outputDirectory: outputDir
    };
  }
}

// Export singleton instance
module.exports = new SchemaLoader();