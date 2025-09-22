// modules/core/validators.js

class DataValidators {
  constructor() {
    // Cache for loaded schemas
    this.schemaCache = {};
    this.baseSchemaLoaded = false;
  }

  /**
   * Load and cache the base submission schema
   */
  async loadBaseSchema() {
    if (this.baseSchemaLoaded && this.schemaCache.base) {
      return this.schemaCache.base;
    }

    try {
      const fs = require('fs-extra');
      const path = require('path');
      const schemaPath = path.join(__dirname, '../../data/schemas/base-submission-schema.json');
      
      if (await fs.pathExists(schemaPath)) {
        this.schemaCache.base = await fs.readJson(schemaPath);
        this.baseSchemaLoaded = true;
        return this.schemaCache.base;
      }
    } catch (error) {
      console.warn('Could not load base schema:', error.message);
    }
    
    return null;
  }

  /**
   * Validate submission structure against base schema
   */
  async validateSubmissionStructure(submission) {
    const baseSchema = await this.loadBaseSchema();
    
    if (!baseSchema) {
      // Fallback validation if base schema not available
      return this.validateBasicStructure(submission);
    }

    const errors = [];
    
    // Check required top-level fields
    if (!submission.metadata) {
      errors.push('Missing required field: metadata');
    } else {
      // Validate metadata structure
      const metadataErrors = this.validateMetadata(submission.metadata, baseSchema);
      errors.push(...metadataErrors);
    }
    
    if (!submission.dataType) {
      errors.push('Missing required field: dataType');
    } else if (!['threatActor', 'malware', 'technique', 'incident', 'attackVector'].includes(submission.dataType)) {
      errors.push(`Invalid dataType: ${submission.dataType}`);
    }
    
    if (!submission.data) {
      errors.push('Missing required field: data');
    } else if (!Array.isArray(submission.data)) {
      errors.push('Field "data" must be an array');
    } else if (submission.data.length === 0) {
      errors.push('Field "data" cannot be empty');
    }
    
    return {
      valid: errors.length === 0,
      errors: errors
    };
  }

  /**
   * Validate metadata against base schema requirements
   */
  validateMetadata(metadata, baseSchema) {
    const errors = [];
    
    // Required metadata fields
    const requiredFields = ['version', 'org', 'submissionDate'];
    
    for (const field of requiredFields) {
      if (!metadata[field]) {
        errors.push(`Missing required metadata field: ${field}`);
      }
    }
    
    // Validate version format
    if (metadata.version && !/^\d+\.\d+$/.test(metadata.version)) {
      errors.push('Invalid version format. Expected: "X.Y" (e.g., "1.0")');
    }
    
    // Validate org format
    if (metadata.org && !/^[a-zA-Z0-9-_]+$/.test(metadata.org)) {
      errors.push('Invalid org format. Use only alphanumeric characters, hyphens, and underscores');
    }
    
    // Validate submissionDate
    if (metadata.submissionDate && !this.validateDateTime(metadata.submissionDate)) {
      errors.push('Invalid submissionDate format. Expected ISO 8601 format');
    }
    
    // Validate reportingPeriod if present
    if (metadata.reportingPeriod) {
      if (!metadata.reportingPeriod.start || !metadata.reportingPeriod.end) {
        errors.push('reportingPeriod must have both start and end dates');
      } else {
        if (!this.validateDateTime(metadata.reportingPeriod.start)) {
          errors.push('Invalid reportingPeriod.start format');
        }
        if (!this.validateDateTime(metadata.reportingPeriod.end)) {
          errors.push('Invalid reportingPeriod.end format');
        }
        if (new Date(metadata.reportingPeriod.start) > new Date(metadata.reportingPeriod.end)) {
          errors.push('reportingPeriod.start must be before reportingPeriod.end');
        }
      }
    }
    
    // Validate TLP classification
    if (metadata.classification && !this.validateTLP(metadata.classification)) {
      errors.push(`Invalid TLP classification: ${metadata.classification}`);
    }
    
    // Validate record count matches data array length (if possible to check)
    if (metadata.recordCount !== undefined && metadata.recordCount < 0) {
      errors.push('recordCount cannot be negative');
    }
    
    return errors;
  }

  /**
   * Fallback basic structure validation
   */
  validateBasicStructure(submission) {
    const errors = [];
    
    if (!submission.metadata) {
      errors.push('Missing required field: metadata');
    }
    
    if (!submission.dataType) {
      errors.push('Missing required field: dataType');
    }
    
    if (!submission.data) {
      errors.push('Missing required field: data');
    } else if (!Array.isArray(submission.data)) {
      errors.push('Field "data" must be an array');
    }
    
    return {
      valid: errors.length === 0,
      errors: errors
    };
  }

  /**
   * Main validation method - validates against base schema and specific schema
   */
  async validateSubmission(submission, specificSchema) {
    const results = {
      valid: true,
      errors: [],
      warnings: []
    };
    
    // First, validate against base schema structure
    const structureValidation = await this.validateSubmissionStructure(submission);
    
    if (!structureValidation.valid) {
      results.valid = false;
      results.errors.push(...structureValidation.errors.map(e => `[Structure] ${e}`));
    }
    
    // Validate record count matches actual data
    if (submission.metadata?.recordCount !== undefined && 
        submission.data && 
        submission.metadata.recordCount !== submission.data.length) {
      results.warnings.push(
        `Record count mismatch: metadata.recordCount=${submission.metadata.recordCount}, actual=${submission.data.length}`
      );
    }
    
    // Validate each record against specific schema
    if (specificSchema && submission.data && Array.isArray(submission.data)) {
      const recordErrors = [];
      
      submission.data.forEach((record, index) => {
        const recordValidation = this.validateRecord(record, specificSchema);
        if (!recordValidation.valid) {
          recordErrors.push(`[Record ${index}] ${recordValidation.errors.join(', ')}`);
        }
      });
      
      if (recordErrors.length > 0) {
        results.valid = false;
        results.errors.push(...recordErrors);
      }
    }
    
    return results;
  }

  validateRecord(data, schema) {
    const errors = [];
    const validated = {};

    if (!schema || !schema.fields) {
      // If no schema, pass through data
      return { valid: true, data: data, errors: [] };
    }

    // Check required fields
    for (const [field, config] of Object.entries(schema.fields)) {
      if (config.required && !data[field]) {
        errors.push(`Missing required field: ${field}`);
        continue;
      }

      if (data[field] !== undefined) {
        // Type validation
        if (!this.validateType(data[field], config.type)) {
          errors.push(`Invalid type for ${field}: expected ${config.type}`);
          continue;
        }

        // Enum validation
        if (config.values && !config.values.includes(data[field])) {
          errors.push(`Invalid value for ${field}: must be one of ${config.values.join(', ')}`);
          continue;
        }

        // Pattern validation
        if (config.pattern) {
          const regex = new RegExp(config.pattern);
          if (!regex.test(data[field])) {
            errors.push(`Invalid format for ${field}: must match ${config.pattern}`);
            continue;
          }
        }

        // Range validation for numbers
        if (config.type === 'number') {
          if (config.min !== undefined && data[field] < config.min) {
            errors.push(`${field} must be at least ${config.min}`);
            continue;
          }
          if (config.max !== undefined && data[field] > config.max) {
            errors.push(`${field} must be at most ${config.max}`);
            continue;
          }
        }

        validated[field] = data[field];
      }
    }

    // Include any additional fields not in schema
    for (const [field, value] of Object.entries(data)) {
      if (!(field in validated)) {
        validated[field] = value;
      }
    }

    return {
      valid: errors.length === 0,
      errors: errors,
      data: validated
    };
  }

  validateType(value, type) {
    switch (type) {
      case 'string':
        return typeof value === 'string';
      case 'number':
        return typeof value === 'number' && !isNaN(value);
      case 'boolean':
        return typeof value === 'boolean';
      case 'array':
        return Array.isArray(value);
      case 'object':
        return typeof value === 'object' && !Array.isArray(value) && value !== null;
      case 'date':
        return !isNaN(Date.parse(value));
      case 'enum':
        return true; // Handled separately
      default:
        return true; // Unknown types pass through
    }
  }

  validateDateTime(dateString) {
    // Validate ISO 8601 format
    const iso8601Pattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?(Z|[+-]\d{2}:\d{2})?$/;
    
    if (!iso8601Pattern.test(dateString)) {
      return false;
    }
    
    const date = new Date(dateString);
    return !isNaN(date.getTime());
  }

  validateIOC(ioc) {
    // Validate indicators of compromise
    const validations = {
      md5: /^[a-f0-9]{32}$/i,
      sha1: /^[a-f0-9]{40}$/i,
      sha256: /^[a-f0-9]{64}$/i,
      sha512: /^[a-f0-9]{128}$/i,
      domain: /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i,
      ipv4: /^(\d{1,3}\.){3}\d{1,3}$/,
      ipv6: /^([0-9a-f]{0,4}:){7}[0-9a-f]{0,4}$/i,
      url: /^https?:\/\/.+$/i,
      email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    };

    for (const [type, pattern] of Object.entries(validations)) {
      if (pattern.test(ioc)) {
        return { valid: true, type: type };
      }
    }

    return { valid: false, type: 'unknown' };
  }

  validateTechniqueId(id) {
    // MITRE ATT&CK technique ID format
    const pattern = /^T\d{4}(\.\d{3})?$/;
    return pattern.test(id);
  }

  validateCVE(cve) {
    // CVE ID format
    const pattern = /^CVE-\d{4}-\d{4,}$/;
    return pattern.test(cve);
  }

  validateTLP(classification) {
    const validTLP = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:RED'];
    return validTLP.includes(classification);
  }

  validateSeverity(severity) {
    const validSeverity = ['critical', 'high', 'medium', 'low', 'informational'];
    return validSeverity.includes(severity?.toLowerCase());
  }

  validateHealthcareSector(sector) {
    const validSectors = [
      'hospital', 'insurance', 'pharma', 'medical_device',
      'clinic', 'laboratory', 'nursing_home', 'rehabilitation',
      'telehealth', 'other'
    ];
    return validSectors.includes(sector?.toLowerCase());
  }

  validateDateRange(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    
    if (isNaN(start) || isNaN(end)) {
      return { valid: false, error: 'Invalid date format' };
    }
    
    if (start > end) {
      return { valid: false, error: 'Start date must be before end date' };
    }
    
    // Check if dates are not in the future
    const now = new Date();
    if (end > now) {
      return { valid: false, error: 'End date cannot be in the future' };
    }
    
    return { valid: true };
  }

  /**
   * Validate hash format and type
   */
  validateHash(hash) {
    if (typeof hash === 'string') {
      return this.validateIOC(hash);
    }
    
    if (typeof hash === 'object' && hash.type && hash.value) {
      const validation = this.validateIOC(hash.value);
      const typeMatches = hash.type.toLowerCase() === validation.type;
      
      return {
        valid: validation.valid && typeMatches,
        type: hash.type,
        message: !typeMatches ? `Hash type mismatch: declared ${hash.type}, detected ${validation.type}` : null
      };
    }
    
    return { valid: false, type: 'unknown' };
  }

  sanitizeString(str) {
    // Remove potentially harmful characters
    if (typeof str !== 'string') return str;
    
    return str
      .replace(/[<>]/g, '') // Remove HTML tags
      .replace(/[\u0000-\u001F\u007F-\u009F]/g, '') // Remove control characters
      .trim();
  }

  sanitizeData(data) {
    if (typeof data === 'string') {
      return this.sanitizeString(data);
    }
    
    if (Array.isArray(data)) {
      return data.map(item => this.sanitizeData(item));
    }
    
    if (typeof data === 'object' && data !== null) {
      const sanitized = {};
      for (const [key, value] of Object.entries(data)) {
        sanitized[key] = this.sanitizeData(value);
      }
      return sanitized;
    }
    
    return data;
  }

  /**
   * Comprehensive validation summary
   */
  generateValidationSummary(results) {
    const summary = {
      totalErrors: results.errors?.length || 0,
      totalWarnings: results.warnings?.length || 0,
      valid: results.valid,
      timestamp: new Date().toISOString(),
      details: {
        structureErrors: results.errors?.filter(e => e.includes('[Structure]')).length || 0,
        recordErrors: results.errors?.filter(e => e.includes('[Record')).length || 0,
        criticalErrors: results.errors?.filter(e => 
          e.includes('Missing required') || 
          e.includes('Invalid dataType')
        ).length || 0
      }
    };
    
    return summary;
  }
}

module.exports = { DataValidators };