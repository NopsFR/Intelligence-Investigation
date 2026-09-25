import { describe, expect, it } from "vitest";
import { isBlockedIp } from "./ssrf";

describe("isBlockedIp", () => {
  it("blocks loopback addresses", () => {
    expect(isBlockedIp("127.0.0.1")).toBe(true);
    expect(isBlockedIp("::1")).toBe(true);
  });

  it("blocks private IPv4 ranges", () => {
    expect(isBlockedIp("10.0.0.5")).toBe(true);
    expect(isBlockedIp("172.16.0.1")).toBe(true);
    expect(isBlockedIp("172.31.255.255")).toBe(true);
    expect(isBlockedIp("192.168.1.1")).toBe(true);
  });

  it("blocks link-local and cloud metadata addresses", () => {
    expect(isBlockedIp("169.254.169.254")).toBe(true);
    expect(isBlockedIp("169.254.0.1")).toBe(true);
  });

  it("blocks IPv6 unique-local and link-local addresses", () => {
    expect(isBlockedIp("fe80::1")).toBe(true);
    expect(isBlockedIp("fc00::1")).toBe(true);
    expect(isBlockedIp("fd12:3456::1")).toBe(true);
  });

  it("blocks IPv4-mapped IPv6 addresses that resolve to private ranges", () => {
    expect(isBlockedIp("::ffff:127.0.0.1")).toBe(true);
    expect(isBlockedIp("::ffff:10.0.0.1")).toBe(true);
  });

  it("allows public IPv4 addresses", () => {
    expect(isBlockedIp("8.8.8.8")).toBe(false);
    expect(isBlockedIp("1.1.1.1")).toBe(false);
  });

  it("allows public IPv6 addresses", () => {
    expect(isBlockedIp("2606:4700:4700::1111")).toBe(false);
  });

  it("blocks unrecognized/malformed input by default", () => {
    expect(isBlockedIp("not-an-ip")).toBe(true);
    expect(isBlockedIp("")).toBe(true);
  });

  it("blocks the 172.16.0.0/12 boundary correctly without over-blocking 172.32+", () => {
    expect(isBlockedIp("172.32.0.1")).toBe(false);
    expect(isBlockedIp("172.15.255.255")).toBe(false);
  });
});
