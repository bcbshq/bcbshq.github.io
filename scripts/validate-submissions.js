// scripts/validate-submissions.js
const fs = require('fs-extra');
const path = require('path');
const Ajv = require('ajv');

async function validateSubmissions() {
  console.log('='.repeat(60));
  console.log('Validating Threat Intelligence Submissions');
  console.log('='.repeat(60));
  console.log('');

  const ajv = new Ajv({ 
    allErrors: true,
    verbose: true,
    strict: false
  });

  try {
    // Load schemas
    const schemas = await loadSchemas();
    console.log(`Loaded ${Object.keys(schemas).length} validation schemas`);
    console.log('');

    // Get input directory
    const inputDir = path.join(__dirname, '../data/input');
    await fs.ensureDir(inputDir);
    
    const subsidiaries = await getSubsidiaries(inputDir);
    
    if (subsidiaries.length === 0) {
      console.log('No org directories found to validate.');
      return;
    }

    console.log(`Found ${subsidiaries.length} subsidiaries to validate:`);
    console.log(subsidiaries.map(s => `  - ${s}`).join('\n'));
    console.log('');

    let totalFiles = 0;
    let validFiles = 0;
    let invalidFiles = 0;
    const errors = [];

    // Validate each org's submissions
    for (const org of subsidiaries) {
      console.log(`\nValidating ${org}:`);
      console.log('-'.repeat(40));
      
      const subDir = path.join(inputDir, org);
      const files = await fs.readdir(subDir);
      const jsonFiles = files.filter(f => f.endsWith('.json'));
      
      if (jsonFiles.length === 0) {
        console.log('  No JSON files found');
        continue;
      }

      for (const file of jsonFiles) {
        totalFiles++;
        const filePath = path.join(subDir, file);
        
        try {
          const content = await fs.readJson(filePath);
          const validation = await validateFile(content, schemas, ajv);
          
          if (validation.valid) {
            console.log(`  ✓ ${file} - Valid (${validation.dataType}, ${validation.recordCount} records)`);
            validFiles++;
          } else {
            console.error(`  ✗ ${file} - Invalid`);
            console.error(`    Errors: ${validation.errors.join('; ')}`);
            invalidFiles++;
            errors.push({
              org,
              file,
              errors: validation.errors
            });
          }
        } catch (error) {
          console.error(`  ✗ ${file} - Failed to parse`);
          console.error(`    Error: ${error.message}`);
          invalidFiles++;
          errors.push({
            org,
            file,
            errors: [`Failed to parse JSON: ${error.message}`]
          });
        }
      }
    }

    // Summary
    console.log('');
    console.log('='.repeat(60));
    console.log('Validation Summary:');
    console.log(`  Total files: ${totalFiles}`);
    console.log(`  Valid files: ${validFiles}`);
    console.log(`  Invalid files: ${invalidFiles}`);
    
    if (errors.length > 0) {
      console.log('');
      console.log('Validation Errors:');
      for (const error of errors) {
        console.log(`  ${error.org}/${error.file}:`);
        error.errors.forEach(e => console.log(`    - ${e}`));
      }
      
      // Exit with error code if validation failed
      process.exit(1);
    } else {
      console.log('');
      console.log('✓ All submissions are valid!');
    }

  } catch (error) {
    console.error('Validation process failed:', error);
    process.exit(1);
  }
}

async function loadSchemas() {
  const schemas = {};
  const schemaDir = path.join(__dirname, '../data/schemas');
  
  // Ensure schema directory exists
  await fs.ensureDir(schemaDir);
  
  // Define default schemas if files don't exist
  const defaultSchemas = {
    'threat-actor': {
      type: 'object',
      required: ['metadata', 'dataType', 'data'],
      properties: {
        metadata: {
          type: 'object',
          required: ['version', 'org', 'submissionDate'],
          properties: {
            version: { type: 'string' },
            org: { type: 'string' },
            submissionDate: { type: 'string', format: 'date-time' }
          }
        },
        dataType: { const: 'threatActor' },
        data: {
          type: 'array',
          items: {
            type: 'object',
            required: ['name', 'type', 'org', 'telemetryDate'],
            properties: {
              name: { type: 'string' },
              type: { type: 'string' },
              org: { type: 'string' },
              telemetryDate: { type: 'string' }
            }
          }
        }
      }
    },
    'malware': {
      type: 'object',
      required: ['metadata', 'dataType', 'data'],
      properties: {
        metadata: { type: 'object' },
        dataType: { const: 'malware' },
        data: { type: 'array' }
      }
    },
    'technique': {
      type: 'object',
      required: ['metadata', 'dataType', 'data'],
      properties: {
        metadata: { type: 'object' },
        dataType: { const: 'technique' },
        data: { type: 'array' }
      }
    },
    'incident': {
      type: 'object',
      required: ['metadata', 'dataType', 'data'],
      properties: {
        metadata: { type: 'object' },
        dataType: { const: 'incident' },
        data: { type: 'array' }
      }
    },
    'attack-vector': {
      type: 'object',
      required: ['metadata', 'dataType', 'data'],
      properties: {
        metadata: { type: 'object' },
        dataType: { const: 'attackVector' },
        data: { type: 'array' }
      }
    }
  };

  // Try to load schemas from files, use defaults if not found
  for (const [name, defaultSchema] of Object.entries(defaultSchemas)) {
    const schemaFile = path.join(schemaDir, `${name}-schema.json`);
    
    try {
      if (await fs.pathExists(schemaFile)) {
        schemas[name] = await fs.readJson(schemaFile);
        console.log(`  Loaded schema: ${name}`);
      } else {
        schemas[name] = defaultSchema;
        // Save default schema for future use
        await fs.writeJson(schemaFile, defaultSchema, { spaces: 2 });
        console.log(`  Created default schema: ${name}`);
      }
    } catch (error) {
      console.warn(`  Failed to load ${name} schema, using default`);
      schemas[name] = defaultSchema;
    }
  }

  return schemas;
}

async function validateFile(content, schemas, ajv) {
  const result = {
    valid: false,
    dataType: content.dataType || 'unknown',
    recordCount: 0,
    errors: []
  };

  // Check basic structure
  if (!content.metadata) {
    result.errors.push('Missing metadata section');
    return result;
  }

  if (!content.dataType) {
    result.errors.push('Missing dataType field');
    return result;
  }

  if (!content.data) {
    result.errors.push('Missing data section');
    return result;
  }

  // Get appropriate schema
  const schemaMap = {
    'threatActor': 'threat-actor',
    'malware': 'malware',
    'technique': 'technique',
    'incident': 'incident',
    'attackVector': 'attack-vector'
  };

  const schemaName = schemaMap[content.dataType];
  if (!schemaName || !schemas[schemaName]) {
    result.errors.push(`Unknown or unsupported dataType: ${content.dataType}`);
    return result;
  }

  // Validate against schema
  const validate = ajv.compile(schemas[schemaName]);
  const valid = validate(content);

  if (valid) {
    result.valid = true;
    result.recordCount = Array.isArray(content.data) ? content.data.length : 1;
  } else {
    result.errors = validate.errors.map(err => {
      return `${err.instancePath || 'root'}: ${err.message}`;
    });
  }

  return result;
}

async function getSubsidiaries(inputDir) {
  const entries = await fs.readdir(inputDir, { withFileTypes: true });
  return entries
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
    .filter(name => !name.startsWith('.'));
}

// Run validation
validateSubmissions();