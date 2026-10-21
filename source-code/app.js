/**
 * SCTPForge Pro - Application Controller
 * Version: 1.0.0
 */

document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  // Form Inputs
  const inputSrcPort = document.getElementById('input-src-port');
  const inputDstPort = document.getElementById('input-dst-port');
  const inputVtag = document.getElementById('input-vtag');
  const inputChecksumAlgo = document.getElementById('input-checksum-algo');
  const inputChunkType = document.getElementById('input-chunk-type');
  const inputPpid = document.getElementById('input-ppid');
  const inputStreams = document.getElementById('input-streams');
  const inputNumIps = document.getElementById('input-num-ips');
  const inputPayload = document.getElementById('input-payload');

  const checkMultiHoming = document.getElementById('check-multi-homing');
  const checkAuthChunks = document.getElementById('check-auth-chunks');
  const checkPmtud = document.getElementById('check-pmtud');
  const checkGtsm = document.getElementById('check-gtsm');

  const badgePresetStatus = document.getElementById('badge-preset-status');
  const badgeWireframeStatus = document.getElementById('badge-wireframe-status');
  const badgeFailoverStatus = document.getElementById('badge-failover-status');
  const badgeAuditGrade = document.getElementById('badge-audit-grade');

  // Metrics
  const valPacketLen = document.getElementById('val-packet-len');
  const valChunkLen = document.getElementById('val-chunk-len');
  const valPaddingBytes = document.getElementById('val-padding-bytes');
  const valVtagDisp = document.getElementById('val-vtag-disp');
  const wireframeHexOutput = document.getElementById('wireframe-hex-output');
  const labelChecksumHex = document.getElementById('label-checksum-hex');

  // Failover Elements
  const inputRtoInitial = document.getElementById('input-rto-initial');
  const inputRtoMax = document.getElementById('input-rto-max');
  const inputPathRetrans = document.getElementById('input-path-retrans');
  const inputAssocRetrans = document.getElementById('input-assoc-retrans');
  const inputHbInterval = document.getElementById('input-hb-interval');
  const inputLinkBw = document.getElementById('input-link-bw');
  const inputRtt = document.getElementById('input-rtt');

  const valBestFailover = document.getElementById('val-best-failover');
  const valWorstFailover = document.getElementById('val-worst-failover');
  const valBdpMb = document.getElementById('val-bdp-mb');
  const valArwndMb = document.getElementById('val-arwnd-mb');
  const labelFailoverVerdict = document.getElementById('label-failover-verdict');

  // Audit & Synthesizer
  const auditChecklistEl = document.getElementById('audit-checklist-el');
  const codeOutputEl = document.getElementById('code-output-el');
  const btnCopyCode = document.getElementById('btn-copy-code');
  const btnRunAudit = document.getElementById('btn-run-audit');

  // Profile Export / Import
  const btnExportJson = document.getElementById('btn-export-json');
  const btnImportJson = document.getElementById('btn-import-json');
  const fileImport = document.getElementById('file-import');

  let activePreset = '5g-sa-n2-ngap';
  let activeTab = 'open5gs';

  const PRESETS = {
    '5g-sa-n2-ngap': {
      srcPort: 38412,
      dstPort: 38412,
      vTag: '0x1A2B3C4D',
      checksumAlgo: 'CRC32C',
      chunkType: 0,
      ppid: 60,
      streams: 16,
      numIps: 2,
      payload: '5G-NGAP-INITIAL-UE-MESSAGE',
      multiHoming: true,
      authChunks: true,
      pmtud: true,
      gtsm: true,
      rtoInitial: 1000,
      rtoMax: 5000,
      pathRetrans: 5,
      assocRetrans: 10,
      hbInterval: 30000,
      linkBw: 1000,
      rtt: 20
    },
    '4g-lte-s1-mme-s1ap': {
      srcPort: 36412,
      dstPort: 36412,
      vTag: '0x2C3D4E5F',
      checksumAlgo: 'CRC32C',
      chunkType: 0,
      ppid: 18,
      streams: 8,
      numIps: 2,
      payload: '4G-S1AP-INITIAL-CONTEXT-SETUP',
      multiHoming: true,
      authChunks: true,
      pmtud: true,
      gtsm: true,
      rtoInitial: 1000,
      rtoMax: 5000,
      pathRetrans: 4,
      assocRetrans: 8,
      hbInterval: 20000,
      linkBw: 500,
      rtt: 30
    },
    'vulnerable-insecure-sctp': {
      srcPort: 9999,
      dstPort: 9999,
      vTag: '0x00000000',
      checksumAlgo: 'ADLER32',
      chunkType: 0,
      ppid: 0,
      streams: 1,
      numIps: 1,
      payload: 'CLEAR-TEXT-SIGNALLING',
      multiHoming: false,
      authChunks: false,
      pmtud: false,
      gtsm: false,
      rtoInitial: 3000,
      rtoMax: 60000,
      pathRetrans: 6,
      assocRetrans: 4,
      hbInterval: 0,
      linkBw: 100,
      rtt: 50
    }
  };

  function loadPreset(key) {
    const p = PRESETS[key];
    if (!p) return;
    activePreset = key;

    document.querySelectorAll('.btn-preset').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.preset === key);
    });

    inputSrcPort.value = p.srcPort;
    inputDstPort.value = p.dstPort;
    inputVtag.value = p.vTag;
    inputChecksumAlgo.value = p.checksumAlgo;
    inputChunkType.value = p.chunkType;
    inputPpid.value = p.ppid;
    inputStreams.value = p.streams;
    inputNumIps.value = p.numIps;
    inputPayload.value = p.payload;

    checkMultiHoming.checked = p.multiHoming;
    checkAuthChunks.checked = p.authChunks;
    checkPmtud.checked = p.pmtud;
    checkGtsm.checked = p.gtsm;

    inputRtoInitial.value = p.rtoInitial;
    inputRtoMax.value = p.rtoMax;
    inputPathRetrans.value = p.pathRetrans;
    inputAssocRetrans.value = p.assocRetrans;
    inputHbInterval.value = p.hbInterval;
    inputLinkBw.value = p.linkBw;
    inputRtt.value = p.rtt;

    if (key === 'vulnerable-insecure-sctp') {
      badgePresetStatus.className = 'badge badge-rose';
      badgePresetStatus.textContent = 'High Telecom Outage Risk';
    } else {
      badgePresetStatus.className = 'badge badge-green';
      badgePresetStatus.textContent = 'Carrier Grade Hardened';
    }

    updateCalculations();
  }

  function updateCalculations() {
    const srcPort = Number(inputSrcPort.value) || 38412;
    const dstPort = Number(inputDstPort.value) || 38412;
    let vTagNum = parseInt(inputVtag.value, 16);
    if (isNaN(vTagNum)) vTagNum = 0x1A2B3C4D;
    const chunkType = Number(inputChunkType.value) || 0;
    const ppid = Number(inputPpid.value) || 60;
    const payload = inputPayload.value || '5G-NGAP-SIGNAL';

    // 1. Packet Encoding & Wireframe
    const pkt = SCTPProtocolEngine.encodeSCTPPacket({
      srcPort,
      dstPort,
      vTag: vTagNum,
      chunkType,
      ppid,
      payload
    });

    valPacketLen.textContent = `${pkt.totalLength} B`;
    valChunkLen.textContent = `${pkt.chunkLength} B`;
    valPaddingBytes.textContent = `${pkt.paddingCount} B`;
    valVtagDisp.textContent = pkt.vTagHex;
    labelChecksumHex.textContent = `CRC32c: ${pkt.checksumHex}`;
    wireframeHexOutput.textContent = pkt.hexString;

    if (inputChecksumAlgo.value === 'CRC32C') {
      badgeWireframeStatus.className = 'badge badge-cyan';
      badgeWireframeStatus.textContent = 'Valid Castagnoli CRC32c';
    } else {
      badgeWireframeStatus.className = 'badge badge-rose';
      badgeWireframeStatus.textContent = 'Adler-32 Collision Risk';
    }

    // 2. Multi-Homing Failover & BDP Sizing
    const rtoInit = Number(inputRtoInitial.value) || 1000;
    const rtoMax = Number(inputRtoMax.value) || 5000;
    const pathRetrans = Number(inputPathRetrans.value) || 5;
    const assocRetrans = Number(inputAssocRetrans.value) || 10;
    const hbInt = Number(inputHbInterval.value) || 30000;
    const linkBw = Number(inputLinkBw.value) || 1000;
    const rtt = Number(inputRtt.value) || 20;

    const fRes = SCTPProtocolEngine.calculatePathFailover({
      rtoInitialMs: rtoInit,
      rtoMinMs: 200,
      rtoMaxMs: rtoMax,
      pathMaxRetrans: pathRetrans,
      assocMaxRetrans: assocRetrans,
      hbIntervalMs: hbInt,
      numPaths: Number(inputNumIps.value) || 2
    });

    const bRes = SCTPProtocolEngine.calculateWindowBdp({
      linkBandwidthMbps: linkBw,
      rttMs: rtt
    });

    valBestFailover.textContent = `${fRes.bestCaseFailoverSec} s`;
    valWorstFailover.textContent = `${fRes.worstCaseFailoverSec} s`;
    valBdpMb.textContent = `${bRes.bdpMb} MB`;
    valArwndMb.textContent = `${bRes.recommendedArwndMb} MB`;

    if (fRes.isAssocRetransSafe) {
      badgeFailoverStatus.className = 'badge badge-green';
      badgeFailoverStatus.textContent = 'Hierarchy Safe';
      labelFailoverVerdict.innerHTML = `<span style="color: var(--accent-green); font-weight: 700;">Hierarchy Valid:</span> Assoc.Max.Retrans (${assocRetrans}) >= Path.Max.Retrans (${pathRetrans}) * 1.5. Secondary path failover will complete cleanly without tearing down the entire 5G association.`;
    } else {
      badgeFailoverStatus.className = 'badge badge-rose';
      badgeFailoverStatus.textContent = 'Hierarchy Inverted';
      labelFailoverVerdict.innerHTML = `<span style="color: var(--accent-rose); font-weight: 700;">CRITICAL HIERARCHY FAILURE:</span> Assoc.Max.Retrans (${assocRetrans}) is too low relative to Path.Max.Retrans (${pathRetrans}). Entire session will abort BEFORE path failover can complete!`;
    }

    runAudit();
    updateSynthesizer();
  }

  function runAudit() {
    const auditConfig = {
      checksumAlgo: inputChecksumAlgo.value,
      multiHomingEnabled: checkMultiHoming.checked,
      numIpAddresses: Number(inputNumIps.value) || 2,
      vTagRandomized: inputVtag.value !== '0x00000000',
      cookieHmacSha256: activePreset !== 'vulnerable-insecure-sctp',
      cookieLifetimeSec: activePreset === 'vulnerable-insecure-sctp' ? 300 : 30,
      pathMaxRetrans: Number(inputPathRetrans.value) || 5,
      assocMaxRetrans: Number(inputAssocRetrans.value) || 10,
      authChunksEnabled: checkAuthChunks.checked,
      addIpEnabled: activePreset === '5g-sa-n2-ngap',
      numOutStreams: Number(inputStreams.value) || 16,
      numInStreams: Number(inputStreams.value) || 16,
      pmtudEnabled: checkPmtud.checked,
      maxPacketSizeBytes: checkPmtud.checked ? 1400 : 1600,
      heartbeatEnabled: Number(inputHbInterval.value) > 0,
      hbIntervalMs: Number(inputHbInterval.value) || 30000,
      gtsmEnabled: checkGtsm.checked,
      targetPort: Number(inputDstPort.value) || 38412
    };

    const audit = SCTPSecurityAuditor.auditSctpEndpoint(auditConfig);

    badgeAuditGrade.textContent = `Grade ${audit.grade} (${audit.percentage}%)`;
    if (audit.percentage >= 90) {
      badgeAuditGrade.className = 'badge badge-green';
    } else if (audit.percentage >= 70) {
      badgeAuditGrade.className = 'badge badge-amber';
    } else {
      badgeAuditGrade.className = 'badge badge-rose';
    }

    auditChecklistEl.innerHTML = '';
    audit.results.forEach(res => {
      const item = document.createElement('div');
      item.className = 'audit-item';
      item.innerHTML = `
        <div class="audit-left">
          <div class="audit-title">${res.name}</div>
          <div class="audit-desc">${res.details}</div>
        </div>
        <div class="audit-badge ${res.passed ? 'badge-green' : 'badge-rose'}">
          ${res.passed ? 'PASS (' + res.score + '/' + res.maxScore + ')' : 'FAIL (' + res.score + '/' + res.maxScore + ')'}
        </div>
      `;
      auditChecklistEl.appendChild(item);
    });
  }

  function updateSynthesizer() {
    const params = {
      primaryIp: '10.200.1.10',
      secondaryIp: '10.200.2.10',
      port: Number(inputDstPort.value) || 38412,
      rtoInitial: Number(inputRtoInitial.value) || 1000,
      rtoMin: 200,
      rtoMax: Number(inputRtoMax.value) || 5000,
      pathMaxRetrans: Number(inputPathRetrans.value) || 5,
      assocMaxRetrans: Number(inputAssocRetrans.value) || 10,
      hbInterval: Number(inputHbInterval.value) || 30000,
      profileName: 'SCTP-5G-AMF-PROFILE'
    };

    let code = '';
    if (activeTab === 'open5gs') {
      code = SCTPConfigSynthesizer.generateOpen5GS(params);
    } else if (activeTab === 'sysctl') {
      code = SCTPConfigSynthesizer.generateLinuxSysctl(params);
    } else if (activeTab === 'cisco') {
      code = SCTPConfigSynthesizer.generateCisco(params);
    } else if (activeTab === 'nokia') {
      code = SCTPConfigSynthesizer.generateNokia(params);
    } else if (activeTab === 'prometheus') {
      code = SCTPConfigSynthesizer.generatePrometheus(params);
    }
    codeOutputEl.textContent = code;
  }

  // Presets
  document.querySelectorAll('.btn-preset').forEach(btn => {
    btn.addEventListener('click', () => {
      loadPreset(btn.dataset.preset);
    });
  });

  // Tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeTab = btn.dataset.tab;
      updateSynthesizer();
    });
  });

  // Inputs
  [inputSrcPort, inputDstPort, inputVtag, inputChecksumAlgo, inputChunkType,
   inputPpid, inputStreams, inputNumIps, inputPayload, checkMultiHoming,
   checkAuthChunks, checkPmtud, checkGtsm, inputRtoInitial, inputRtoMax,
   inputPathRetrans, inputAssocRetrans, inputHbInterval, inputLinkBw, inputRtt].forEach(el => {
    el.addEventListener('input', updateCalculations);
    el.addEventListener('change', updateCalculations);
  });

  // Copy code
  btnCopyCode.addEventListener('click', () => {
    navigator.clipboard.writeText(codeOutputEl.textContent).then(() => {
      btnCopyCode.textContent = 'Copied!';
      setTimeout(() => { btnCopyCode.textContent = 'Copy Code'; }, 2000);
    });
  });

  // Export JSON
  btnExportJson.addEventListener('click', () => {
    const profile = {
      schema: 'sctpforge-pro-profile-v1',
      timestamp: new Date().toISOString(),
      activePreset,
      settings: {
        srcPort: Number(inputSrcPort.value),
        dstPort: Number(inputDstPort.value),
        vTag: inputVtag.value,
        checksumAlgo: inputChecksumAlgo.value,
        chunkType: Number(inputChunkType.value),
        ppid: Number(inputPpid.value),
        streams: Number(inputStreams.value),
        numIps: Number(inputNumIps.value),
        payload: inputPayload.value,
        multiHoming: checkMultiHoming.checked,
        authChunks: checkAuthChunks.checked,
        pmtud: checkPmtud.checked,
        gtsm: checkGtsm.checked,
        rtoInitial: Number(inputRtoInitial.value),
        rtoMax: Number(inputRtoMax.value),
        pathRetrans: Number(inputPathRetrans.value),
        assocRetrans: Number(inputAssocRetrans.value),
        hbInterval: Number(inputHbInterval.value),
        linkBw: Number(inputLinkBw.value),
        rtt: Number(inputRtt.value)
      }
    };
    const blob = new Blob([JSON.stringify(profile, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sctpforge-profile-${activePreset}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Import JSON
  btnImportJson.addEventListener('click', () => {
    fileImport.click();
  });

  fileImport.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const data = JSON.parse(event.target.result);
        if (data.settings) {
          inputSrcPort.value = data.settings.srcPort || 38412;
          inputDstPort.value = data.settings.dstPort || 38412;
          inputVtag.value = data.settings.vTag || '0x1A2B3C4D';
          inputChecksumAlgo.value = data.settings.checksumAlgo || 'CRC32C';
          inputChunkType.value = data.settings.chunkType || 0;
          inputPpid.value = data.settings.ppid || 60;
          inputStreams.value = data.settings.streams || 16;
          inputNumIps.value = data.settings.numIps || 2;
          inputPayload.value = data.settings.payload || '5G-NGAP';
          checkMultiHoming.checked = !!data.settings.multiHoming;
          checkAuthChunks.checked = !!data.settings.authChunks;
          checkPmtud.checked = !!data.settings.pmtud;
          checkGtsm.checked = !!data.settings.gtsm;
          inputRtoInitial.value = data.settings.rtoInitial || 1000;
          inputRtoMax.value = data.settings.rtoMax || 5000;
          inputPathRetrans.value = data.settings.pathRetrans || 5;
          inputAssocRetrans.value = data.settings.assocRetrans || 10;
          inputHbInterval.value = data.settings.hbInterval || 30000;
          inputLinkBw.value = data.settings.linkBw || 1000;
          inputRtt.value = data.settings.rtt || 20;
          updateCalculations();
          alert('SCTP Profile loaded successfully!');
        }
      } catch (err) {
        alert('Invalid JSON profile format.');
      }
    };
    reader.readAsText(file);
  });

  btnRunAudit.addEventListener('click', () => {
    updateCalculations();
    alert(`Audit Completed: ${badgeAuditGrade.textContent}`);
  });

  // Initial Load
  loadPreset('5g-sa-n2-ngap');
});
