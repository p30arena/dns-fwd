/*
 * A Node.js DNS server with in-memory caching, retries, and timeouts.
 * Listens on UDP port 53 and forwards DNS queries to Cloudflare's DoH service
 * via a SOCKS5 proxy.
 *
 * Required packages:
 *   - dns-packet: to decode/encode DNS messages
 *   - node-fetch: to perform HTTP requests
 *   - socks-proxy-agent: to tunnel HTTP requests via a SOCKS5 proxy
 *
 * Install with:
 *   npm install dns-packet node-fetch socks-proxy-agent
 *
 * Note: Binding to port 53 may require elevated privileges.
 */

import { createSocket } from "dgram";
import { decode, encode } from "dns-packet";
import fetch from "node-fetch";
import { SocksProxyAgent } from "socks-proxy-agent";
import * as Bottleneck from "bottleneck";

// Configuration values
// Use hostname to avoid TLS/SNI issues
const DOH_URL = "https://1.1.1.1/dns-query";
const SOCKS_PROXY = "socks5://127.0.0.1:1080"; // Your SOCKS5 proxy address

// Create a UDP server socket
const server = createSocket("udp4");

// In-memory cache: key => { packet: decoded DNS packet, timestamp: Date.now() }
const cache = {};

// Configure Bottleneck (adjust minTime as needed)
const limiter = new Bottleneck.default({
  maxConcurrent: 1,
  minTime: 100, // 100 ms between requests; adjust based on your rate limit needs
});

// Utility to compute a cache key from the query questions
function getCacheKey(query) {
  // For simplicity, we use the JSON string of the questions array.
  return JSON.stringify(query.questions);
}

// Utility to update TTL values in a cached packet based on elapsed time (in seconds)
function updateTTLs(packet, elapsedSeconds) {
  if (packet.answers && Array.isArray(packet.answers)) {
    packet.answers = packet.answers.map((answer) => {
      // Subtract elapsed time from the original TTL, ensuring it doesn't drop below 0
      const newTTL = Math.max(0, answer.ttl - elapsedSeconds);
      return { ...answer, ttl: newTTL };
    });
  }
  return packet;
}

// Helper: perform a fetch with retries and a timeout (per attempt)
async function fetchWithRetry(url, options, retries = 3, timeout = 5000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      // Wrap the fetch call in the limiter.schedule
      const response = await limiter.schedule(() =>
        fetch(url, {
          ...options,
          signal: controller.signal,
        })
      );
      clearTimeout(timer);
      return response;
    } catch (error) {
      clearTimeout(timer);
      console.warn(`Attempt ${attempt} failed: ${error.message}`);
      if (attempt === retries) {
        throw error;
      }
      // Optional: wait a bit before retrying (exponential backoff could be added here)
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}

server.on("error", (err) => {
  console.error(`Server error:\n${err.stack}`);
  server.close();
});

server.on("message", async (msg, rinfo) => {
  console.log(`Received DNS query from ${rinfo.address}:${rinfo.port}`);

  let query;
  try {
    query = decode(msg);
  } catch (error) {
    console.error("Failed to decode DNS query:", error);
    return;
  }

  // Create a cache key based on the query's questions
  const cacheKey = getCacheKey(query);

  // Check if we have a valid cached response
  const cached = cache[cacheKey];
  if (cached) {
    const elapsedSeconds = (Date.now() - cached.timestamp) / 1000;
    // Determine the minimum TTL among all answer records in the cached packet
    const originalTTLs = cached.packet.answers.map((answer) => answer.ttl);
    const minTTL = Math.min(...originalTTLs);

    if (elapsedSeconds < minTTL) {
      // Cache is still valid; create a deep copy of the cached packet
      const cachedPacket = JSON.parse(JSON.stringify(cached.packet));
      // Update TTLs to account for the elapsed time
      updateTTLs(cachedPacket, elapsedSeconds);
      // Set the header ID to match the client's query
      cachedPacket.id = query.id;
      const responseBuffer = encode(cachedPacket);
      console.log("Serving response from cache.");
      server.send(responseBuffer, rinfo.port, rinfo.address, (err) => {
        if (err) console.error("Error sending cached response:", err);
      });
      return;
    } else {
      console.log("Cache expired for key:", cacheKey);
      delete cache[cacheKey];
    }
  }

  // No valid cache entry, so query the DoH endpoint
  try {
    console.log("Querying DoH for:", query.questions);
    const agent = new SocksProxyAgent(SOCKS_PROXY, {
      rejectUnauthorized: false,
    });

    // Use fetchWithRetry to perform the DoH request with a 5s timeout per attempt
    const response = await fetchWithRetry(
      DOH_URL,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/dns-message",
          Accept: "application/dns-message",
        },
        body: msg,
        agent: agent,
      },
      3, // max 3 attempts
      5000 // 5 seconds timeout per attempt
    );

    if (!response.ok) {
      throw new Error(`DoH query failed with status ${response.status}`);
    }

    const dohResponseBuffer = Buffer.from(await response.arrayBuffer());
    let dohPacket;
    try {
      dohPacket = decode(dohResponseBuffer);
    } catch (err) {
      console.error("Failed to decode DoH response:", err);
      return;
    }

    // Cache the decoded DNS response along with the current timestamp
    cache[cacheKey] = {
      packet: dohPacket,
      timestamp: Date.now(),
    };

    // Update the response packet header to match the client's query ID
    dohPacket.id = query.id;
    const responseBuffer = encode(dohPacket);
    server.send(responseBuffer, rinfo.port, rinfo.address, (err) => {
      if (err) console.error("Error sending response:", err);
    });
  } catch (error) {
    console.error("Error processing DNS query:", error);
  }
});

server.on("listening", () => {
  const address = server.address();
  console.log(`DNS server listening on ${address.address}:${address.port}`);
});

// Bind the server to UDP port 53
server.bind(53);
