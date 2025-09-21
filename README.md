# Threat Landscape Platform

A collaborative, modular threat landscape platform for organizations to share and analyze internal telemetry data.

## Overview

This platform enables multiple organizations to contribute threat intelligence data from their internal telemetry, which is then processed through an ETL pipeline to create a unified threat landscape view for the association.

## Quick Start

### Prerequisites
- Node.js 18+
- Git
- GitHub account with repository access

### Installation

```bash
# Clone the repository
git clone https://github.com/bcbshq/bcbshq.github.io.git
cd bcbshq.github.io

# Install dependencies
npm install

# Create required directories
mkdir -p data/input data/processed data/archive data/schemas
mkdir -p data/input/org-a data/input/org-b
```

### Basic Usage

1. **Add threat intelligence data** to your org directory:
```bash
cp templates/threat-actor-template.json data/input/org-a/2025-01-actors.json
```

2. **Validate your data**:
```bash
npm run validate
```

3. **Run the ETL pipeline**:
```bash
npm run etl
```

4. **Generate statistics**:
```bash
npm run stats
```

5. **View the dashboard** (local development):
```bash
npm run serve
# Open http://localhost:8080
```

## Data Submission Guide

### Directory Structure

Each org should place their data files in:
```
data/input/{org-name}/
  ├── YYYY-MM-actors.json      # Threat actor data
  ├── YYYY-MM-malware.json     # Malware samples
  ├── YYYY-MM-techniques.json  # MITRE ATT&CK observations
  ├── YYYY-MM-incidents.json   # Incident reports
  └── YYYY-MM-vectors.json     # Attack vector analysis
```

### Data Format

All submissions must follow the standard JSON format:

```json
{
  "metadata": {
    "version": "1.0",
    "org": "your-org-name",
    "submissionDate": "2025-01-15T00:00:00Z",
    "reportingPeriod": {
      "start": "2025-01-01T00:00:00Z",
      "end": "2025-01-31T23:59:59Z"
    },
    "classification": "TLP:GREEN",
    "dataSource": "internal-telemetry"
  },
  "dataType": "threatActor|malware|technique|incident|attackVector",
  "data": [
    // Array of records
  ]
}
```

### Data Schemas

The platform uses strict JSON schemas for validation. All schemas are located in `data/schemas/`:

#### Available Schemas

1. **Base Submission Schema** (`base-submission-schema.json`)
   - Common structure for ALL submissions
   - Defines metadata requirements
   - Includes shared definitions (TLP, dates, hashes, CVEs)

2. **Threat Actor Schema** (`threat-actor-schema.json`)
   - Required: `name`, `type`, `org`, `telemetryDate`
   - Optional: `aliases`, `ttps`, `malwareUsed`, `infrastructure`, `confidence`
   - Healthcare-specific: `healthcareTargets`, `targetedSectors`

3. **Malware Schema** (`malware-schema.json`)
   - Required: `name`, `type`, `org`, `telemetryDate`
   - Optional: `family`, `capabilities`, `iocs`, `deliveryMethods`
   - IOCs support: MD5/SHA1/SHA256 hashes, domains, IPs, URLs

4. **Technique Schema** (`technique-schema.json`)
   - Required: `techniqueId`, `name`, `tactic`, `org`, `telemetryDate`
   - MITRE ATT&CK aligned with proper technique ID format (T####.###)
   - Supports all 12 ATT&CK tactics

5. **Incident Schema** (`incident-schema.json`)
   - Required: `id`, `sector`, `attackType`, `org`, `telemetryDate`
   - Impact metrics: `financialImpact`, `operationalImpact`, `patientCareImpact`
   - Compliance: `regulatoryImpact` with HIPAA reporting flags

6. **Attack Vector Schema** (`attack-vector-schema.json`)
   - Required: `vectorType`, `frequency`, `severity`, `org`, `telemetryDate`
   - Risk assessment: `riskScore`, `successRate`, `impactMetrics`
   - Vulnerability tracking: `exploitedVulnerabilities` with CVE support

#### Schema Validation

The platform automatically validates all submissions against these schemas:

```bash
# Validate all submissions in data/input/
npm run validate

# Validate a specific organization's data
node scripts/validate-submissions.js org-name

# Validate a single file against a schema (Python)
python scripts/validate_local.py data/input/org-a/2025-01-actors.json data/schemas/threat-actor-schema.json
```

#### Minimal vs Complete Submissions

Each schema defines:
- **Required fields**: Minimum data needed for a valid submission
- **Optional fields**: Additional context for comprehensive analysis

Example minimal threat actor submission:
```json
{
  "metadata": {
    "version": "1.0",
    "org": "hospital-west",
    "submissionDate": "2025-01-15T12:00:00Z"
  },
  "dataType": "threatActor",
  "data": [
    {
      "name": "LockBit 3.0",
      "type": "ransomware",
      "org": "hospital-west",
      "telemetryDate": "2025-01-14T16:45:00Z"
    }
  ]
}
```

### Templates

Use the provided templates in the `templates/` directory:
- `threat-actor-template.json` - Threat actor observations
- `malware-template.json` - Malware analysis
- `technique-template.json` - MITRE ATT&CK techniques
- `incident-template.json` - Incident reports
- `attack-vector-template.json` - Attack vector data

Each template includes all optional fields with example values.

## ETL Pipeline

The ETL pipeline processes submissions through these stages:

1. **Extract**: Read data from org directories
2. **Validate**: Check against JSON schemas
3. **Transform**: Normalize and standardize data
4. **Deduplicate**: Merge duplicate records
5. **Aggregate**: Create summary statistics
6. **Load**: Save to `data/processed/`

### Configuration

Configure the ETL via environment variables:
- `DEDUP_STRATEGY`: `merge`, `latest`, or `aggregate` (default: `merge`)
- `AGG_PERIOD`: `daily`, `weekly`, `monthly`, or `quarterly` (default: `monthly`)
- `ARCHIVE_AFTER_PROCESS`: `true` or `false` (default: `false`)

### Manual Execution

```bash
# Validate all submissions
npm run validate

# Run ETL with custom settings
DEDUP_STRATEGY=aggregate AGG_PERIOD=weekly npm run etl

# Generate statistics report
npm run stats
```

### Automated Processing

The GitHub Actions workflow runs automatically:
- **Schedule**: Every Monday at 2 AM UTC
- **Trigger**: On push to `data/input/`
- **Manual**: Via GitHub Actions UI

## Data Classification

Follow Traffic Light Protocol (TLP) for data classification:
- **TLP:CLEAR** - Public information
- **TLP:GREEN** - Community sharing allowed
- **TLP:AMBER** - Limited distribution
- **TLP:RED** - Internal use only

All schemas enforce TLP classification in both metadata and individual records.

## Security Considerations

1. **No PHI/PII**: Never include patient data or personally identifiable information
2. **Sanitization**: All data is sanitized during processing
3. **Access Control**: Use GitHub teams for org access
4. **Audit Trail**: All changes tracked via Git history
5. **Schema Validation**: Strict validation prevents malformed or malicious data

## API Output

Processed data is available in JSON format:
- `/data/processed/threat-actors.json` - Deduplicated threat actors
- `/data/processed/malware.json` - Malware families and variants
- `/data/processed/techniques.json` - MITRE ATT&CK techniques
- `/data/processed/incidents.json` - Aggregated incidents by period
- `/data/processed/attack-vectors.json` - Attack vector analysis
- `/data/processed/mappings.json` - Actor→Malware→Technique relationships
- `/data/processed/metadata.json` - Processing metadata
- `/data/processed/statistics.json` - Statistical analysis

## Contributing

### Submission Workflow

1. Create a branch:
```bash
git checkout -b org-name/YYYY-MM-submission
```

2. Add your data files:
```bash
cp your-data.json data/input/org-name/
```

3. Validate locally:
```bash
npm run validate
```

4. Commit and push:
```bash
git add data/input/org-name/
git commit -m "Org Name: January 2025 submission"
git push origin org-name/YYYY-MM-submission
```

5. Create a pull request

### Code Contributions

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Schema Development

### Adding Custom Fields

Organizations can propose schema extensions by:

1. Creating an issue describing the new field(s)
2. Providing example data and use cases
3. Submitting a PR with schema updates

### Schema Versioning

- Schemas use semantic versioning (e.g., "1.0", "1.1", "2.0")
- Breaking changes increment major version
- New optional fields increment minor version
- All submissions must specify schema version in metadata

## Troubleshooting

### Common Issues

**Validation Errors**
```bash
# Check specific org
ls data/input/org-name/

# Validate single file
node scripts/validate-submissions.js org-name

# View detailed validation errors
npm run validate -- --verbose
```

**Schema Mismatch**
```bash
# Ensure data matches schema version
cat data/schemas/threat-actor-schema.json | jq '.properties.metadata.properties.version'

# Update templates if schemas change
cp templates/threat-actor-template.json data/input/org-name/actors-backup.json
```

**ETL Failures**
```bash
# Check logs
cat logs/etl-*.log

# Run with verbose output
DEBUG=* npm run etl

# Process single org
SUBSIDIARIES=org-name npm run etl
```

**Missing Dependencies**
```bash
# Reinstall packages
rm -rf node_modules package-lock.json
npm install
```

## Support

- **Documentation**: See `/docs` folder
- **Schema Reference**: See `/data/schemas` folder
- **Issues**: GitHub Issues
- **Contact**: security-team@organization.com

## License

MIT License - See LICENSE file for details

## Compliance

This platform is designed to meet:
- HIPAA Security Rule requirements (with PHI detection and TLP classification)
- GDPR data protection standards (data minimization and sanitization)
- Industry threat intelligence sharing guidelines (STIX/TAXII compatibility planned)

## Schema Features

### Advanced Validation

- **Pattern Matching**: IDs, MITRE techniques, CVEs, hashes
- **Enumerations**: Predefined values for consistency
- **Range Validation**: Confidence scores (0-100), CVSS (0-10)
- **Format Validation**: ISO 8601 dates, email, URLs, IPs

### Healthcare-Specific Fields

- **Sectors**: hospital, insurance, pharma, medical_device, clinic, laboratory
- **Assets**: EHR, medical devices, PHI, backup systems
- **Impact**: Patient care impact levels (critical to none)
- **Compliance**: HIPAA reportable flags, regulatory notifications

### Interoperability

- **MITRE ATT&CK**: Full technique and tactic support
- **CVE**: Vulnerability tracking
- **IOCs**: Multiple hash formats, defanged URLs/domains
- **TLP**: Traffic Light Protocol for data sharing

---

**Last Updated**: September 2025
**Version**: 1.1.0
**Schema Version**: 1.0