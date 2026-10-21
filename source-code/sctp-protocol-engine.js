/**
 * SCTPForge Pro - Protocol Engineering Engine
 * RFC 9260 / RFC 4960 Stream Control Transmission Protocol (SCTP)
 * Features:
 * - 12-Byte Common Header & CRC32c Checksum (RFC 3309)
 * - Binary Chunk Wireframe Encoder & Decoder (DATA, INIT, INIT ACK, SACK, HEARTBEAT, ABORT, SHUTDOWN, AUTH)
 * - Multi-Homing Failover Latency & RTO Waterfall Calculator
 * - Advertised Window (a_rwnd) & BDP Buffer Sizing Engine
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SCTPProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // SCTP Chunk Types (RFC 9260 Section 3.2)
  const CHUNK_TYPES = {
    0: { name: 'DATA', description: 'Payload Data' },
    1: { name: 'INIT', description: 'Initiation' },
    2: { name: 'INIT_ACK', description: 'Initiation Acknowledgment' },
    3: { name: 'SACK', description: 'Selective Acknowledgment' },
    4: { name: 'HEARTBEAT', description: 'Heartbeat Request' },
    5: { name: 'HEARTBEAT_ACK', description: 'Heartbeat Acknowledgment' },
    6: { name: 'ABORT', description: 'Abort Association' },
    7: { name: 'SHUTDOWN', description: 'Shutdown Association' },
    8: { name: 'SHUTDOWN_ACK', description: 'Shutdown Acknowledgment' },
    9: { name: 'ERROR', description: 'Operation Error' },
    10: { name: 'COOKIE_ECHO', description: 'Cookie Echo' },
    11: { name: 'COOKIE_ACK', description: 'Cookie Acknowledgment' },
    12: { name: 'ECNE', description: 'ECN Echo' },
    13: { name: 'CWR', description: 'Congestion Window Reduced' },
    14: { name: 'SHUTDOWN_COMPLETE', description: 'Shutdown Complete' },
    15: { name: 'AUTH', description: 'Authentication Chunk (RFC 4895)' },
    128: { name: 'ASCONF', description: 'Address Configuration (RFC 5061)' },
    129: { name: 'ASCONF_ACK', description: 'Address Configuration Ack' },
    130: { name: 'FORWARD_TSN', description: 'Forward TSN (RFC 3758 PR-SCTP)' }
  };

  // Well-Known Telecom Payload Protocol Identifiers (PPID)
  const TELECOM_PPIDS = {
    0: 'Reserved / Unspecified',
    3: 'IETF SIGTRAN M3UA (RFC 4666)',
    18: '3GPP S1AP (4G LTE eNodeB to MME)',
    46: '3GPP X2AP (LTE Inter-eNodeB Handover)',
    60: '3GPP NGAP (5G gNodeB to AMF - TS 38.413)',
    61: '3GPP XnAP (5G Inter-gNodeB Handover)',
    62: '3GPP E1AP (gNodeB-CU-CP to gNodeB-CU-UP)',
    63: '3GPP F1AP (gNodeB-CU to gNodeB-DU)',
    68: '3GPP W-AGF to AMF',
    50: 'WebRTC DCEP (Data Channel Establishment)',
    51: 'WebRTC String (RFC 8832)',
    53: 'WebRTC Binary (RFC 8832)'
  };

  /**
   * RFC 3309 / RFC 9260 CRC32c Polynomial: 0x1EDC6F41 (Castagnoli)
   * Bit-reflected polynomial: 0x82F63B78
   */
  const CRC32C_TABLE = new Uint32Array(256);
  (function initCRC32cTable() {
    const poly = 0x82F63B78;
    for (let i = 0; i < 256; i++) {
      let crc = i;
      for (let j = 0; j < 8; j++) {
        crc = (crc & 1) ? (crc >>> 1) ^ poly : (crc >>> 1);
      }
      CRC32C_TABLE[i] = crc >>> 0;
    }
  })();

  function calculateCRC32c(buffer) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < buffer.length; i++) {
      const byte = buffer[i];
      crc = (crc >>> 8) ^ CRC32C_TABLE[(crc ^ byte) & 0xFF];
    }
    crc = crc ^ 0xFFFFFFFF;
    // Format into network byte order (little-endian byte reflection per RFC 3309)
    return crc >>> 0;
  }

  /**
   * Encode an SCTP Packet with 12-Byte Common Header + Chunks
   */
  function encodeSCTPPacket(params) {
    const srcPort = params.srcPort || 38412; // 5G NGAP default
    const dstPort = params.dstPort || 38412;
    const vTag = params.vTag !== undefined ? params.vTag : 0x1A2B3C4D;
    const chunkType = params.chunkType !== undefined ? params.chunkType : 0; // DATA
    const chunkFlags = params.chunkFlags !== undefined ? params.chunkFlags : 0x07; // U, B, E = 7
    const payload = params.payload || '5G-NGAP-INITIAL-UE-MESSAGE';

    let chunkPayloadBytes = [];
    if (chunkType === 0) {
      // DATA Chunk Payload:
      // TSN (4 bytes) + Stream ID (2 bytes) + SSN (2 bytes) + PPID (4 bytes) + User Data
      const tsn = params.tsn !== undefined ? params.tsn : 1001;
      const sid = params.sid !== undefined ? params.sid : 1;
      const ssn = params.ssn !== undefined ? params.ssn : 0;
      const ppid = params.ppid !== undefined ? params.ppid : 60; // 5G NGAP

      chunkPayloadBytes.push((tsn >>> 24) & 0xFF, (tsn >>> 16) & 0xFF, (tsn >>> 8) & 0xFF, tsn & 0xFF);
      chunkPayloadBytes.push((sid >>> 8) & 0xFF, sid & 0xFF);
      chunkPayloadBytes.push((ssn >>> 8) & 0xFF, ssn & 0xFF);
      chunkPayloadBytes.push((ppid >>> 24) & 0xFF, (ppid >>> 16) & 0xFF, (ppid >>> 8) & 0xFF, ppid & 0xFF);

      // Append user text
      for (let i = 0; i < payload.length; i++) {
        chunkPayloadBytes.push(payload.charCodeAt(i) & 0xFF);
      }
    } else if (chunkType === 1 || chunkType === 2) {
      // INIT or INIT ACK Chunk:
      // Initiate Tag (4B) + a_rwnd (4B) + Outbound Streams (2B) + Inbound Streams (2B) + Initial TSN (4B)
      const initTag = params.initTag !== undefined ? params.initTag : 0x98765432;
      const arwnd = params.arwnd !== undefined ? params.arwnd : 1048576; // 1MB
      const os = params.os !== undefined ? params.os : 16;
      const mis = params.mis !== undefined ? params.mis : 16;
      const initialTsn = params.initialTsn !== undefined ? params.initialTsn : 50000;

      chunkPayloadBytes.push((initTag >>> 24) & 0xFF, (initTag >>> 16) & 0xFF, (initTag >>> 8) & 0xFF, initTag & 0xFF);
      chunkPayloadBytes.push((arwnd >>> 24) & 0xFF, (arwnd >>> 16) & 0xFF, (arwnd >>> 8) & 0xFF, arwnd & 0xFF);
      chunkPayloadBytes.push((os >>> 8) & 0xFF, os & 0xFF);
      chunkPayloadBytes.push((mis >>> 8) & 0xFF, mis & 0xFF);
      chunkPayloadBytes.push((initialTsn >>> 24) & 0xFF, (initialTsn >>> 16) & 0xFF, (initialTsn >>> 8) & 0xFF, initialTsn & 0xFF);
    } else if (chunkType === 3) {
      // SACK Chunk:
      // Cumulative TSN Ack (4B) + a_rwnd (4B) + Num Gap Ack Blocks (2B) + Num Duplicate TSNs (2B)
      const cumTsn = params.cumTsn !== undefined ? params.cumTsn : 1001;
      const arwnd = params.arwnd !== undefined ? params.arwnd : 1048576;
      chunkPayloadBytes.push((cumTsn >>> 24) & 0xFF, (cumTsn >>> 16) & 0xFF, (cumTsn >>> 8) & 0xFF, cumTsn & 0xFF);
      chunkPayloadBytes.push((arwnd >>> 24) & 0xFF, (arwnd >>> 16) & 0xFF, (arwnd >>> 8) & 0xFF, arwnd & 0xFF);
      chunkPayloadBytes.push(0x00, 0x00); // 0 gap blocks
      chunkPayloadBytes.push(0x00, 0x00); // 0 dup TSNs
    } else if (chunkType === 4 || chunkType === 5) {
      // HEARTBEAT / HEARTBEAT ACK:
      // Heartbeat Info TLV: Type=1 (2B) + Length (2B) + Timestamp/Nonce (8B)
      chunkPayloadBytes.push(0x00, 0x01); // Heartbeat Info parameter type
      chunkPayloadBytes.push(0x00, 0x0C); // Length = 12 bytes
      const nowMs = Date.now();
      const high = Math.floor(nowMs / 0x100000000);
      const low = nowMs >>> 0;
      chunkPayloadBytes.push((high >>> 24) & 0xFF, (high >>> 16) & 0xFF, (high >>> 8) & 0xFF, high & 0xFF);
      chunkPayloadBytes.push((low >>> 24) & 0xFF, (low >>> 16) & 0xFF, (low >>> 8) & 0xFF, low & 0xFF);
    } else {
      for (let i = 0; i < payload.length; i++) {
        chunkPayloadBytes.push(payload.charCodeAt(i) & 0xFF);
      }
    }

    const chunkLen = 4 + chunkPayloadBytes.length;
    // Calculate padding to 4-byte boundary
    const paddingCount = (4 - (chunkLen % 4)) % 4;

    // Build raw packet without checksum
    const raw = [];
    // 12-Byte Common Header
    raw.push((srcPort >>> 8) & 0xFF, srcPort & 0xFF);
    raw.push((dstPort >>> 8) & 0xFF, dstPort & 0xFF);
    raw.push((vTag >>> 24) & 0xFF, (vTag >>> 16) & 0xFF, (vTag >>> 8) & 0xFF, vTag & 0xFF);
    raw.push(0x00, 0x00, 0x00, 0x00); // Checksum placeholder

    // Chunk Header
    raw.push(chunkType & 0xFF);
    raw.push(chunkFlags & 0xFF);
    raw.push((chunkLen >>> 8) & 0xFF, chunkLen & 0xFF);

    // Chunk Payload
    for (let b of chunkPayloadBytes) {
      raw.push(b);
    }

    // Padding bytes
    for (let p = 0; p < paddingCount; p++) {
      raw.push(0x00);
    }

    // Calculate CRC32c over the whole packet with checksum field = 0
    const crc = calculateCRC32c(raw);
    // Insert CRC32c at bytes 8-11 in Little-Endian / Network format per RFC 3309
    raw[8] = crc & 0xFF;
    raw[9] = (crc >>> 8) & 0xFF;
    raw[10] = (crc >>> 16) & 0xFF;
    raw[11] = (crc >>> 24) & 0xFF;

    const hexString = raw.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');

    return {
      srcPort,
      dstPort,
      vTag,
      vTagHex: '0x' + vTag.toString(16).padStart(8, '0').toUpperCase(),
      checksum: crc,
      checksumHex: '0x' + crc.toString(16).padStart(8, '0').toUpperCase(),
      chunkType,
      chunkTypeName: CHUNK_TYPES[chunkType] ? CHUNK_TYPES[chunkType].name : 'UNKNOWN',
      chunkFlags,
      chunkLength: chunkLen,
      paddingCount,
      totalLength: raw.length,
      bytes: raw,
      hexString
    };
  }

  /**
   * Decode an SCTP Packet from raw bytes or hex string
   */
  function decodeSCTPPacket(input) {
    let bytes = [];
    if (typeof input === 'string') {
      const cleaned = input.replace(/[^0-9A-Fa-f]/g, '');
      for (let i = 0; i < cleaned.length; i += 2) {
        bytes.push(parseInt(cleaned.substr(i, 2), 16));
      }
    } else if (Array.isArray(input)) {
      bytes = input;
    }

    if (bytes.length < 12) {
      throw new Error(`SCTP Packet too short: ${bytes.length} bytes (Minimum 12 bytes for Common Header).`);
    }

    const srcPort = (bytes[0] << 8) | bytes[1];
    const dstPort = (bytes[2] << 8) | bytes[3];
    const vTag = ((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]) >>> 0;
    const checksum = ((bytes[11] << 24) | (bytes[10] << 16) | (bytes[9] << 8) | bytes[8]) >>> 0;

    // Verify CRC32c
    const testBytes = [...bytes];
    testBytes[8] = 0; testBytes[9] = 0; testBytes[10] = 0; testBytes[11] = 0;
    const computedCrc = calculateCRC32c(testBytes);
    const checksumValid = (computedCrc === checksum);

    // Parse chunks
    const chunks = [];
    let offset = 12;
    while (offset + 4 <= bytes.length) {
      const cType = bytes[offset];
      const cFlags = bytes[offset + 1];
      const cLen = (bytes[offset + 2] << 8) | bytes[offset + 3];

      if (cLen < 4) {
        break; // Malformed chunk
      }

      const payloadEnd = Math.min(offset + cLen, bytes.length);
      const payloadBytes = bytes.slice(offset + 4, payloadEnd);
      const padding = (4 - (cLen % 4)) % 4;

      const chunkObj = {
        type: cType,
        typeName: CHUNK_TYPES[cType] ? CHUNK_TYPES[cType].name : `TYPE_${cType}`,
        flags: cFlags,
        length: cLen,
        paddingBytes: padding,
        payloadLength: payloadBytes.length
      };

      if (cType === 0 && payloadBytes.length >= 12) {
        // DATA
        chunkObj.tsn = ((payloadBytes[0] << 24) | (payloadBytes[1] << 16) | (payloadBytes[2] << 8) | payloadBytes[3]) >>> 0;
        chunkObj.sid = (payloadBytes[4] << 8) | payloadBytes[5];
        chunkObj.ssn = (payloadBytes[6] << 8) | payloadBytes[7];
        chunkObj.ppid = ((payloadBytes[8] << 24) | (payloadBytes[9] << 16) | (payloadBytes[10] << 8) | payloadBytes[11]) >>> 0;
        chunkObj.ppidName = TELECOM_PPIDS[chunkObj.ppid] || `PPID_${chunkObj.ppid}`;
        chunkObj.isUnordered = !!(cFlags & 0x04);
        chunkObj.isBeginning = !!(cFlags & 0x02);
        chunkObj.isEnding = !!(cFlags & 0x01);
      } else if ((cType === 1 || cType === 2) && payloadBytes.length >= 16) {
        // INIT / INIT ACK
        chunkObj.initTag = ((payloadBytes[0] << 24) | (payloadBytes[1] << 16) | (payloadBytes[2] << 8) | payloadBytes[3]) >>> 0;
        chunkObj.arwnd = ((payloadBytes[4] << 24) | (payloadBytes[5] << 16) | (payloadBytes[6] << 8) | payloadBytes[7]) >>> 0;
        chunkObj.os = (payloadBytes[8] << 8) | payloadBytes[9];
        chunkObj.mis = (payloadBytes[10] << 8) | payloadBytes[11];
        chunkObj.initialTsn = ((payloadBytes[12] << 24) | (payloadBytes[13] << 16) | (payloadBytes[14] << 8) | payloadBytes[15]) >>> 0;
      }

      chunks.push(chunkObj);
      offset += cLen + padding;
    }

    return {
      srcPort,
      dstPort,
      vTag,
      vTagHex: '0x' + vTag.toString(16).padStart(8, '0').toUpperCase(),
      checksum,
      checksumHex: '0x' + checksum.toString(16).padStart(8, '0').toUpperCase(),
      computedChecksumHex: '0x' + computedCrc.toString(16).padStart(8, '0').toUpperCase(),
      checksumValid,
      totalLength: bytes.length,
      chunks
    };
  }

  /**
   * Multi-Homing Failover Latency & RTO Waterfall Calculator
   * RFC 9260 Section 6.3.2 / 8.2 Path Failure Detection
   */
  function calculatePathFailover(params) {
    const rtoInitialMs = params.rtoInitialMs !== undefined ? Number(params.rtoInitialMs) : 1000;
    const rtoMinMs = params.rtoMinMs !== undefined ? Number(params.rtoMinMs) : 200;
    const rtoMaxMs = params.rtoMaxMs !== undefined ? Number(params.rtoMaxMs) : 5000;
    const pathMaxRetrans = params.pathMaxRetrans !== undefined ? Number(params.pathMaxRetrans) : 5;
    const assocMaxRetrans = params.assocMaxRetrans !== undefined ? Number(params.assocMaxRetrans) : 10;
    const hbIntervalMs = params.hbIntervalMs !== undefined ? Number(params.hbIntervalMs) : 30000;
    const numPaths = params.numPaths !== undefined ? Number(params.numPaths) : 2;

    const backoffRtos = [];
    let currentRto = rtoInitialMs;
    let totalRetransTimeMs = 0;

    for (let k = 0; k < pathMaxRetrans; k++) {
      backoffRtos.push(currentRto);
      totalRetransTimeMs += currentRto;
      currentRto = Math.min(currentRto * 2, rtoMaxMs);
    }

    // Failover latency: Time for Path.Max.Retrans consecutive timeouts + active probe window
    const worstCaseFailoverSec = Number(((totalRetransTimeMs + hbIntervalMs) / 1000).toFixed(2));
    const bestCaseFailoverSec = Number((totalRetransTimeMs / 1000).toFixed(2));

    // Audit rule: Assoc.Max.Retrans must be >= Path.Max.Retrans * numPaths to prevent association abort before failover
    const isAssocRetransSafe = assocMaxRetrans >= (pathMaxRetrans * 1.5);

    return {
      rtoInitialMs,
      rtoMinMs,
      rtoMaxMs,
      pathMaxRetrans,
      assocMaxRetrans,
      hbIntervalMs,
      numPaths,
      backoffRtos,
      totalRetransTimeMs,
      bestCaseFailoverSec,
      worstCaseFailoverSec,
      isAssocRetransSafe,
      recommendedAssocMaxRetrans: Math.max(assocMaxRetrans, pathMaxRetrans * 2)
    };
  }

  /**
   * Calculate BDP & Receiver Window (a_rwnd) Sizing for Line-Rate Signaling
   */
  function calculateWindowBdp(params) {
    const linkBandwidthMbps = params.linkBandwidthMbps !== undefined ? Number(params.linkBandwidthMbps) : 1000; // 1 Gbps
    const rttMs = params.rttMs !== undefined ? Number(params.rttMs) : 20; // 20ms RTT

    const bdpBytes = Math.round((linkBandwidthMbps * 1e6 * (rttMs / 1000.0)) / 8.0);
    const bdpKb = Number((bdpBytes / 1024.0).toFixed(2));
    const bdpMb = Number((bdpBytes / (1024.0 * 1024.0)).toFixed(2));

    // Recommended a_rwnd is 2x BDP for burst absorption
    const recommendedArwndBytes = bdpBytes * 2;
    const recommendedArwndMb = Number((recommendedArwndBytes / (1024.0 * 1024.0)).toFixed(2));

    return {
      linkBandwidthMbps,
      rttMs,
      bdpBytes,
      bdpKb,
      bdpMb,
      recommendedArwndBytes,
      recommendedArwndMb
    };
  }

  return {
    CHUNK_TYPES,
    TELECOM_PPIDS,
    calculateCRC32c,
    encodeSCTPPacket,
    decodeSCTPPacket,
    calculatePathFailover,
    calculateWindowBdp
  };
}));
