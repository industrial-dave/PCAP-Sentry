# Enhanced ML Training with All Data Sources

PCAP Sentry now uses all available data sources to train its machine learning model for improved accuracy.

## Data Sources Integrated

### 1. **Knowledge Base (User-Labeled Data)**
- Safe PCAP captures marked by user
- Malicious PCAP captures marked by user
- Historical analysis results

### 2. **Threat Intelligence (Online Feeds)**
- AlienVault OTX reputation scores
- URLhaus malicious URL database
- Public IP/domain blacklists
- Threat pulse counts and indicators

### 3. **Network Behavior Analysis**
- Protocol distribution (TCP/UDP/Other ratios)
- Top destination ports
- Packet size statistics
- DNS query patterns
- HTTP request patterns
- Unique host counts

## Enhanced Feature Set

The ML model now trains on enriched features including:

### Traditional Network Features
- `packet_count` - Total packets in capture
- `avg_size` - Average packet size
- `dns_query_count` - Number of DNS queries
- `http_request_count` - Number of HTTP requests
- `unique_http_hosts` - Count of unique HTTP hosts
- `proto_ratio` - Protocol distribution (TCP/UDP/Other)
- `top_ports` - Most common destination ports

### Threat Intelligence Features
- `flagged_ip_count` - Number of IPs flagged by threat feeds
- `flagged_domain_count` - Number of domains flagged by threat feeds
- `avg_ip_risk_score` - Average risk score from threat feeds (0-100)
- `avg_domain_risk_score` - Average risk score for domains (0-100)

## How It Works

### Training Process

1. **Data Collection**
   - Gathers all labeled samples from knowledge base
   - Enriches each sample with threat intelligence data
   - Extracts ~50+ features from network behavior

2. **Feature Vectorization**
   - Converts features to numeric format
   - One-hot encoding for categorical variables (ports, protocols)
   - Normalization for consistent model training

3. **Model Training**
   - Algorithm: Logistic Regression with balanced class weights
   - Handles imbalanced datasets (more malware than safe samples)
   - Cross-validates reliability

4. **Feature Importance Analysis**
   - Identifies which features best distinguish safe from malicious
   - Shows top 10 most important predictors

### Analysis Process

When analyzing a PCAP file:

1. Parse traffic and extract network features
2. Query threat intelligence for flagged indicators
3. Combine features into unified feature vector
4. Feed to ML model for prediction
5. Get malicious probability (0-100%)

## Example Output

```
Local Model Verdict
Verdict: Likely Malicious
Malicious confidence: 85.30%
Backend: CPU
```

## Feature Importance Example

```
Top 10 most important features:
  - avg_domain_risk_score: 2.4531
  - flagged_domain_count: 1.8924
  - avg_ip_risk_score: 1.7643
  - http_request_count: 1.2321
  - flagged_ip_count: 0.9876
  - proto_tcp: 0.8765
  - unique_http_hosts: 0.6543
  - port_4444: 0.5432
  - dns_query_count: 0.3210
  - avg_size: 0.1987
```

## Training Requirements

- **Minimum samples**: 2 (one safe, one malicious)
- **Recommended samples**: 20+ per class for reliable model
- **scikit-learn**: Required for ML training

Install with:
```bash
pip install scikit-learn
```

## Model Performance

The model uses:
- **Algorithm**: Logistic Regression
- **Regularization**: L2 with balanced class weights
- **Max iterations**: 2000
- **Solver**: LBFGS

This approach is:
- Fast training and inference
- Interpretable (can see feature importance)
- Robust to imbalanced data
- Works well with mixed feature types

## Automatic Training

The model retrains automatically when:
1. You mark a capture as safe/malicious
2. You import training data from PCAP files
3. You enable "Local model training" in preferences

## Manual Training

To manually trigger training:
1. Mark several PCAP captures (both safe and malicious)
2. Enable "Local model training" in preferences
3. Go to Train tab and import labeled PCAPs
4. Click "Train from Safe" or "Train from Malware"

## Threat Intelligence Impact

When threat intelligence is available:
- Flagged indicators add 20-30 points to risk score
- Unknown/unverified IPs add minimal signal
- Multiple threat feeds increase confidence

Example:
```
Network shows HTTP traffic to 5 hosts
- 3 hosts are flagged as malicious (OTX reputation)
- avg_domain_risk_score = 75.0
- Model confidence in "malicious" increases significantly
```

## Caching and Performance

- Models are saved to: `pcap_sentry_model.pkl`
- Features cached for 1 hour to speed up repeated analysis
- Training takes ~1-5 seconds depending on sample count
- Inference ~50ms per PCAP file

## Troubleshooting

**Model not training:**
1. Ensure scikit-learn is installed: `pip install scikit-learn`
2. Need at least 2 samples (one safe, one malicious)
3. Check debug logs for errors

**Low accuracy:**
1. Add more training samples (20+ ideal)
2. Ensure representative mix of safe and malicious
3. Enable threat intelligence for better features

**Missing threat intelligence features:**
1. Check internet connectivity
2. Verify `requests` library installed
3. Enable threat intelligence in analysis

## References

- [Logistic Regression - Scikit-learn](https://scikit-learn.org/stable/modules/linear_model.html#logistic-regression)
- [Feature Extraction - Scikit-learn](https://scikit-learn.org/stable/modules/feature_extraction.html)
- [Class Imbalance Handling](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html#sklearn.linear_model.LogisticRegression)
