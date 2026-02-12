# Threat Intelligence Integration

PCAP Sentry now includes integration with free/public threat intelligence sources to improve analysis accuracy.

## Features

### Online Threat Feeds
The application now queries the following free threat intelligence sources during analysis:

1. **AlienVault OTX (Open Threat Exchange)**
   - Open, community-driven threat intelligence
   - No API key required
   - Checks IPs and domains against global threat pulses
   - Provides reputation scores and threat pulse counts

2. **URLhaus**
   - Free malware URL database
   - No API key required
   - Identifies known malicious URLs and campaigns
   - Useful for detecting command & control communications

3. **Public IP/Domain Reputation Checks**
   - Cross-references against public threat databases
   - Identifies previously flagged IP addresses
   - Detects known malicious domains

## How It Works

When you analyze a PCAP file, PCAP Sentry now:

1. **Extracts network indicators** from the traffic:
   - IP addresses (sources and destinations)
   - Domain names (from DNS queries and HTTP hosts)
   - URLs

2. **Queries threat intelligence** sources:
   - Checks top IPs against the AlienVault OTX reputation service
   - Queries domains against URLhaus malware URL database
   - Scores each indicator based on threat feed findings

3. **Displays findings** in analysis results:
   - Shows flagged IPs and domains in the "Results" tab
   - Provides detailed context in the "Why This Looks Malicious" tab
   - Includes risk scores from each threat feed

## Results Interpretation

### Risk Scores
- **0-30**: Low risk (likely legitimate)
- **30-70**: Medium risk (requires investigation)
- **70-100**: High risk (likely malicious)

### Result Examples

**Flagged IP Example:**
```
Flagged IPs (from public threat feeds):
  - 192.0.2.55: risk score 85/100
    (AlienVault OTX: 12 pulses)
```

**Flagged Domain Example:**
```
Flagged Domains (from public threat feeds):
  - malicious.example.com: risk score 92/100
    (URLhaus: 15 malicious URLs)
```

## Performance Considerations

- **Network requests**: Threat intelligence checks require internet connectivity
- **Caching**: Results are cached for 1 hour to improve performance
- **Timeouts**: Individual lookups timeout after 5 seconds to avoid delays
- **Sampling**: Only top 10 IPs and domains are checked per analysis

## Configuration

Currently, threat intelligence is **enabled by default** when:
1. The `requests` library is installed (`pip install requests`)
2. Internet connectivity is available

## Limitations

- **Rate limits**: Public APIs may have rate limits
- **Coverage**: Not all IPs/domains will have threat intelligence
- **False positives**: Some legitimate services may be flagged
- **Free tier**: Uses only free/public data sources

## Future Enhancements

Possible future additions:
- VirusTotal free API (requires community API key)
- AbuseIPDB commercial API (optional with API key)
- MaxMind GeoIP (for geolocation-based anomaly detection)
- Custom threat feed support
- Local threat feed caching/updates

## Troubleshooting

**Threat intelligence not showing:**
1. Check internet connectivity
2. Verify `requests` library is installed: `pip install requests`
3. Check PCAP Sentry debug logs for errors

**Slow analysis:**
1. Threat intelligence lookups may add 10-30 seconds
2. Timeouts are set to 5 seconds per lookup
3. Disable by removing threat intelligence imports if needed

## References

- [AlienVault OTX API](https://otx.alienvault.com/api/)
- [URLhaus](https://urlhaus.abuse.ch/)
- [AbuseIPDB](https://www.abuseipdb.com/)
