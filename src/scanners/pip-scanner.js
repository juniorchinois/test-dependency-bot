const axios = require('axios');
const { logger } = require('../utils/logger');
const config = require('../config');

class PipScanner {
  constructor() {
    this.apiClient = axios.create({
      timeout: config.apiTimeout,
      headers: {
        'User-Agent': 'Dependency-Vulnerability-Bot/1.0'
      }
    });
  }

  async scan(requirementsContent, getCache, setCache) {
    const findings = [];

    try {
      // Parse requirements.txt
      const dependencies = this.parseRequirements(requirementsContent);

      if (dependencies.length === 0) {
        logger.info('📦 No dependencies found in requirements.txt');
        return [];
      }

      // Limit number of dependencies
      const depsToScan = dependencies.slice(0, config.maxDependencies);
      logger.info(`🔍 Scanning ${depsToScan.length} pip dependencies`);

      for (const dep of depsToScan) {
        try {
          const vulnerability = await this.checkVulnerability(
            dep.name,
            dep.version,
            getCache,
            setCache
          );

          if (vulnerability) {
            findings.push({
              package: dep.name,
              currentVersion: dep.version,
              vulnerabilities: vulnerability.vulnerabilities,
              recommendedFix: vulnerability.fixedVersion
            });
          }

          await this.delay(100);

        } catch (error) {
          logger.error(`Error scanning ${dep.name}:`, error.message);
        }
      }

      return findings;

    } catch (error) {
      logger.error('Error scanning requirements.txt:', error);
      return [];
    }
  }

  parseRequirements(content) {
    const lines = content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));

    const dependencies = [];

    for (const line of lines) {
      // Handle different formats: package==version, package>=version, package
      const match = line.match(/^([a-zA-Z0-9\-_]+)\s*(?:==|>=|<=|>|<|~=)\s*([0-9.]+)/);
      if (match) {
        dependencies.push({
          name: match[1],
          version: match[2]
        });
      } else {
        // Just package name without version
        const nameMatch = line.match(/^([a-zA-Z0-9\-_]+)/);
        if (nameMatch) {
          // We'll need to check latest version
          dependencies.push({
            name: nameMatch[1],
            version: null
          });
        }
      }
    }

    return dependencies;
  }

  async checkVulnerability(name, version, getCache, setCache) {
    const cacheKey = `pip:${name}:${version || 'latest'}`;

    // Check cache
    const cached = getCache(cacheKey);
    if (cached && cached.timestamp > Date.now() - config.cacheTTL) {
      logger.debug(`Cache hit for ${name}@${version}`);
      return cached.vulnerabilities.length > 0 ? cached : null;
    }

    try {
      // Check OSV API for Python packages
      const result = await this.checkOSV(name, version);

      const cacheResult = {
        vulnerabilities: result?.vulnerabilities || [],
        fixedVersion: result?.fixedVersion || null,
        timestamp: Date.now()
      };

      setCache(cacheKey, cacheResult);

      return cacheResult.vulnerabilities.length > 0 ? cacheResult : null;

    } catch (error) {
      logger.error(`Error checking ${name}@${version}:`, error.message);
      return null;
    }
  }

  async checkOSV(name, version) {
    try {
      
      const requestBody = {
        package: {
          name: name,
          ecosystem: 'PyPI'
        }
      };

      if (version) {
        requestBody.version = version;
      }

      const response = await this.apiClient.post(config.osvApiUrl, requestBody);

      const vulns = response.data.vulns || [];

      const formattedVulns = vulns.map(v => ({
        id: v.id || v.cve,
        severity: this.mapSeverity(v.severity),
        summary: v.summary || 'No description available',
        cve: v.cve || null,
        fixedVersion: this.extractFixedVersion(v),
        source: 'osv',
        publishedDate: v.published || null,
        references: v.references || []
      }));

      const fixedVersion = this.findLatestFixedVersion(vulns);

      return {
        vulnerabilities: formattedVulns,
        fixedVersion: fixedVersion
      };

    } catch (error) {
      if (error.response?.status === 404) {
        return { vulnerabilities: [], fixedVersion: null };
      }
      throw error;
    }
  }

  mapSeverity(severity) {
    if (!severity) return 'UNKNOWN';

    let severityStr = '';

    if (typeof severity === 'string') {
      severityStr = severity;
    } else if (typeof severity === 'object' && severity !== null) {
      // Handle OSV severity object: { type: "CVSS_V3", score: "..." }
      severityStr = severity.type || severity.severity || JSON.stringify(severity);
    } else {
      return 'UNKNOWN';
    }

    const severityMap = {
      'critical': 'CRITICAL',
      'high': 'HIGH',
      'medium': 'MEDIUM',
      'moderate': 'MEDIUM',
      'low': 'LOW',
      'info': 'LOW',
      'cvss_v3': 'MEDIUM',
      'cvss_v4': 'MEDIUM'
    };

    const key = severityStr.toString().toLowerCase();
    return severityMap[key] || 'UNKNOWN';
  }

  extractFixedVersion(vuln) {
    const affected = vuln?.affected || [];
    for (const item of affected) {
      const ranges = item?.ranges || [];
      for (const range of ranges) {
        const events = range?.events || [];
        for (const event of events) {
          if (event.fixed) {
            return event.fixed;
          }
        }
      }
    }
    return null;
  }

  findLatestFixedVersion(vulns) {
    const fixedVersions = vulns
      .map(v => this.extractFixedVersion(v))
      .filter(v => v !== null);

    if (fixedVersions.length === 0) return null;

    // Sort versions (simplified for Python versions)
    const sorted = fixedVersions.sort((a, b) => {
      const partsA = a.split('.').map(Number);
      const partsB = b.split('.').map(Number);

      for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
        const numA = partsA[i] || 0;
        const numB = partsB[i] || 0;
        if (numA !== numB) return numB - numA;
      }
      return 0;
    });

    return sorted[0];
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = { scanPip: (...args) => new PipScanner().scan(...args) };