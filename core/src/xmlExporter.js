export function exportModelAsXML(classifierState) {
  const { classCounts, featureCounts, totalSamples } = classifierState;
  const featureNames = [
    'tag_risk', 'attr_delta', 'script_injection', 'inline_handler',
    'url_anomaly', 'data_uri', 'dom_depth', 'text_entropy'
  ];

  const rules = featureNames.map((name, i) => {
    const pMalicious = (featureCounts.malicious[i] + 1) / (classCounts.malicious + 2);
    const pBenign    = (featureCounts.benign[i]    + 1) / (classCounts.benign    + 2);
    return `    <feature name="${name}" index="${i}">
      <p_malicious>${pMalicious.toFixed(6)}</p_malicious>
      <p_benign>${pBenign.toFixed(6)}</p_benign>
      <log_odds>${(Math.log(pMalicious) - Math.log(pBenign)).toFixed(6)}</log_odds>
    </feature>`;
  }).join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<adaptxss_model version="${classifierState.version}" totalSamples="${totalSamples}">
  <prior_malicious>${(classCounts.malicious / totalSamples).toFixed(6)}</prior_malicious>
  <prior_benign>${(classCounts.benign / totalSamples).toFixed(6)}</prior_benign>
  <features>
${rules}
  </features>
</adaptxss_model>`;
}
