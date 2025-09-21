# Threat Landscape Platform

A collaborative, modular threat landscape platform for  organizations to share and analyze internal telemetry data.

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

### Templates

Use the provided templates in the `templates/` directory:
- `threat-actor-template.json` - Threat actor observations
- `malware-template.json` - Malware analysis
- `technique-template.json` - MITRE ATT&CK techniques
- `incident-template.json` - Incident reports
- `attack-vector-template.json` - Attack vector data

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

## Security Considerations

1. **No PHI/PII**: Never include patient data or personally identifiable information
2. **Sanitization**: All data is sanitized during processing
3. **Access Control**: Use GitHub teams for org access
4. **Audit Trail**: All changes tracked via Git history

## API Output

Processed data is available in JSON format:
- `/data/processed/threat-actors.json`
- `/data/processed/malware.json`
- `/data/processed/techniques.json`
- `/data/processed/incidents.json`
- `/data/processed/attack-vectors.json`
- `/data/processed/mappings.json`
- `/data/processed/metadata.json`
- `/data/processed/statistics.json`

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

## Troubleshooting

### Common Issues

**Validation Errors**
```bash
# Check specific org
ls data/input/org-name/
# Validate single file
node scripts/validate-submissions.js org-name
```

**ETL Failures**
```bash
# Check logs
cat logs/etl-*.log
# Run with verbose output
DEBUG=* npm run etl
```

**Missing Dependencies**
```bash
# Reinstall packages
rm -rf node_modules package-lock.json
npm install
```

## Support

- **Documentation**: See `/docs` folder
- **Issues**: GitHub Issues
- **Contact**: security-team@organization.com

## License

MIT License - See LICENSE file for details

## Compliance

This platform is designed to meet:
- HIPAA Security Rule requirements
- GDPR data protection standards
- Industry threat intelligence sharing guidelines

---

**Last Updated**: September 2025
**Version**: 1.0.0