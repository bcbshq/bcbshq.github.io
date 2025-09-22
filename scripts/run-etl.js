// scripts/run-etl.js
const fs = require('fs-extra');
const path = require('path');
const { ThreatIntelETL } = require('../modules/core/etl');

async function runETL() {
  console.log('='.repeat(60));
  console.log('Threat Landscape ETL Pipeline');
  console.log('='.repeat(60));
  console.log(`Start time: ${new Date().toISOString()}`);
  console.log('');

  try {
    // Get list of organizations
    const organizations = await getOrgList();
    
    if (organizations.length === 0) {
      console.warn('No organization directories found in data/input/');
      console.log('Please ensure org data is placed in data/input/{org-name}/');
      process.exit(0);
    }

    console.log(`Found ${organizations.length} organizations:`, organizations.join(', '));
    console.log('');

    // Check for validation report
    const validationReportPath = path.join(__dirname, '../data/processed/validation-report.json');
    if (await fs.pathExists(validationReportPath)) {
      const validationReport = await fs.readJson(validationReportPath);
      console.log('Previous Validation Results:');
      console.log(`  Valid files: ${validationReport.summary.validFiles}`);
      console.log(`  Invalid files: ${validationReport.summary.invalidFiles}`);
      
      if (validationReport.summary.invalidFiles > 0) {
        console.warn('  ⚠️  Warning: Processing data with validation errors');
      }
      console.log('');
    }

    // Configure ETL
    const config = {
      inputDirectory: path.join(__dirname, '../data/input'),
      outputDirectory: path.join(__dirname, '../data/processed'),
      archiveDirectory: path.join(__dirname, '../data/archive'),
      orgs: organizations,
      deduplicationStrategy: process.env.DEDUP_STRATEGY || 'merge',
      aggregationPeriod: process.env.AGG_PERIOD || 'monthly'
    };

    console.log('ETL Configuration:');
    console.log(`- Organizations: ${config.orgs.length}`);
    console.log(`- Deduplication Strategy: ${config.deduplicationStrategy}`);
    console.log(`- Aggregation Period: ${config.aggregationPeriod}`);
    console.log('');

    // Initialize ETL
    const etl = new ThreatIntelETL(config);

    // Run ETL process
    const result = await etl.processIncomingData();

    // Display results
    console.log('');
    console.log('ETL Process Complete!');
    console.log('-'.repeat(40));
    console.log('Records Processed:');
    console.log(`  Threat Actors: ${result.metadata.recordCounts.threatActors}`);
    console.log(`  Malware: ${result.metadata.recordCounts.malware}`);
    console.log(`  Techniques: ${result.metadata.recordCounts.techniques}`);
    console.log(`  Incidents: ${result.metadata.recordCounts.incidents}`);
    console.log(`  Attack Vectors: ${result.metadata.recordCounts.attackVectors}`);
    console.log('');
    console.log(`Output files saved to: ${config.outputDirectory}`);
    
    // Save ETL summary
    const etlSummary = {
      timestamp: new Date().toISOString(),
      configuration: {
        deduplicationStrategy: config.deduplicationStrategy,
        aggregationPeriod: config.aggregationPeriod
      },
      organizations: config.orgs,
      recordCounts: result.metadata.recordCounts,
      processingTime: {
        start: new Date().toISOString(),
        end: new Date().toISOString()
      }
    };
    
    await fs.writeJson(
      path.join(config.outputDirectory, 'etl-summary.json'),
      etlSummary,
      { spaces: 2 }
    );
    
    // Archive if configured
    if (process.env.ARCHIVE_AFTER_PROCESS === 'true') {
      await archiveRawData(config.archiveDirectory, organizations);
    }

    console.log(`End time: ${new Date().toISOString()}`);
    console.log('='.repeat(60));

  } catch (error) {
    console.error('');
    console.error('ETL FAILED:');
    console.error(error.message);
    console.error('');
    console.error('Stack trace:');
    console.error(error.stack);
    process.exit(1);
  }
}

async function getOrgList() {
  const inputDir = path.join(__dirname, '../data/input');
  
  // Ensure directory exists
  await fs.ensureDir(inputDir);
  
  const entries = await fs.readdir(inputDir, { withFileTypes: true });
  return entries
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
    .filter(name => !name.startsWith('.')); // Ignore hidden directories
}

async function archiveRawData(archiveDir, organizations) {
  const now = new Date();
  const archivePath = path.join(
    archiveDir,
    now.getFullYear().toString(),
    (now.getMonth() + 1).toString().padStart(2, '0'),
    now.getDate().toString().padStart(2, '0')
  );

  console.log(`Archiving raw data to: ${archivePath}`);
  await fs.ensureDir(archivePath);

  const inputDir = path.join(__dirname, '../data/input');
  
  for (const org of organizations) {
    const subDir = path.join(inputDir, org);
    const files = await fs.readdir(subDir);
    
    for (const file of files) {
      if (file.endsWith('.json')) {
        const source = path.join(subDir, file);
        const dest = path.join(archivePath, `${org}-${file}`);
        
        try {
          await fs.copy(source, dest);
          // Optionally remove original after archiving
          if (process.env.DELETE_AFTER_ARCHIVE === 'true') {
            await fs.remove(source);
          }
          console.log(`  Archived: ${org}/${file}`);
        } catch (error) {
          console.error(`  Failed to archive ${source}: ${error.message}`);
        }
      }
    }
  }
}

// Run the ETL process
runETL();