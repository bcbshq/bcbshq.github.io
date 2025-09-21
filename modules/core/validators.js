// modules/core/validators.js

class DataValidators {
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

  validateIOC(ioc) {
    // Validate indicators of compromise
    const validations = {
      md5: /^[a-f0-9]{32}$/i,
      sha1: /^[a-f0-9]{40}$/i,
      sha256: /^[a-f0-9]{64}$/i,
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

  validateTLP(classification) {
    const validTLP = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:RED'];
    return validTLP.includes(classification);
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
}

module.exports = { DataValidators };