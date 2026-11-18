package io.github.chakibselhi.netledger.core.decode;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/** Builds synthetic frames byte by byte, so each test shows exactly what is on the wire. */
public final class TestFrames {

  public static final String BROADCAST = "ff:ff:ff:ff:ff:ff";
  public static final String MDNS_V4_MAC = "01:00:5e:00:00:fb";

  private TestFrames() {}

  public static byte[] mac(String mac) {
    return HexFormat.ofDelimiter(":").parseHex(mac);
  }

  public static byte[] ip(String address) {
    try {
      return InetAddress.getByName(address).getAddress();
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static byte[] ethernet(String destination, String source, int etherType, byte[] payload) {
    var out = new Bytes();
    out.put(mac(destination)).put(mac(source)).u16(etherType).put(payload);
    return out.toByteArray();
  }

  public static byte[] arp(
      int operation, String senderMac, String senderIp, String targetMac, String targetIp) {
    var out = new Bytes();
    out.u16(1).u16(0x0800).u8(6).u8(4).u16(operation);
    out.put(mac(senderMac)).put(ip(senderIp)).put(mac(targetMac)).put(ip(targetIp));
    return out.toByteArray();
  }

  public static byte[] arpFrame(int operation, String senderMac, String senderIp, String targetIp) {
    return ethernet(
        BROADCAST,
        senderMac,
        0x0806,
        arp(operation, senderMac, senderIp, "00:00:00:00:00:00", targetIp));
  }

  public static byte[] ipv4Udp(
      String source, String destination, int sourcePort, int destinationPort, byte[] payload) {
    var udp = udp(sourcePort, destinationPort, payload);
    var out = new Bytes();
    out.u8(0x45).u8(0).u16(20 + udp.length).u16(0).u16(0).u8(64).u8(17).u16(0);
    out.put(ip(source)).put(ip(destination)).put(udp);
    return out.toByteArray();
  }

  public static byte[] ipv6Udp(
      String source, String destination, int sourcePort, int destinationPort, byte[] payload) {
    var udp = udp(sourcePort, destinationPort, payload);
    var out = new Bytes();
    out.u32(0x60000000L).u16(udp.length).u8(17).u8(255);
    out.put(ip(source)).put(ip(destination)).put(udp);
    return out.toByteArray();
  }

  private static byte[] udp(int sourcePort, int destinationPort, byte[] payload) {
    return new Bytes()
        .u16(sourcePort)
        .u16(destinationPort)
        .u16(8 + payload.length)
        .u16(0)
        .put(payload)
        .toByteArray();
  }

  public static byte[] udpFrame(String sourceMac, String sourceIp, int port, byte[] payload) {
    return ethernet(
        MDNS_V4_MAC, sourceMac, 0x0800, ipv4Udp(sourceIp, "224.0.0.251", port, port, payload));
  }

  /** DHCP client message with the given options, each encoded as code, length, value. */
  public static byte[] dhcp(int op, String clientMac, String ciaddr, byte[]... options) {
    var out = new Bytes();
    out.u8(op).u8(1).u8(6).u8(0).u32(0x12345678L).u16(0).u16(0x8000);
    out.put(ip(ciaddr)).put(new byte[12]);
    out.put(mac(clientMac)).put(new byte[10]).put(new byte[64 + 128]);
    out.u32(0x63825363L);
    for (byte[] option : options) {
      out.put(option);
    }
    out.u8(255);
    return out.toByteArray();
  }

  public static byte[] option(int code, byte... value) {
    return new Bytes().u8(code).u8(value.length).put(value).toByteArray();
  }

  public static byte[] option(int code, String value) {
    return option(code, value.getBytes(StandardCharsets.UTF_8));
  }

  public static byte[] dhcpFrame(String clientMac, byte[] dhcp) {
    return ethernet(
        BROADCAST, clientMac, 0x0800, ipv4Udp("0.0.0.0", "255.255.255.255", 68, 67, dhcp));
  }

  /** Uncompressed DNS name from labels. */
  public static byte[] name(String... labels) {
    var out = new Bytes();
    for (String label : labels) {
      byte[] bytes = label.getBytes(StandardCharsets.UTF_8);
      out.u8(bytes.length).put(bytes);
    }
    return out.u8(0).toByteArray();
  }

  public static byte[] record(byte[] name, int type, int recordClass, byte[] rdata) {
    return new Bytes()
        .put(name)
        .u16(type)
        .u16(recordClass)
        .u32(120)
        .u16(rdata.length)
        .put(rdata)
        .toByteArray();
  }

  public static byte[] srv(int port, byte[] target) {
    return new Bytes().u16(0).u16(0).u16(port).put(target).toByteArray();
  }

  public static byte[] txt(String... strings) {
    var out = new Bytes();
    for (String s : strings) {
      byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
      out.u8(bytes.length).put(bytes);
    }
    return out.toByteArray();
  }

  /** DNS message with a header and pre-encoded sections. */
  public static byte[] dns(boolean response, int questions, int answers, byte[]... sections) {
    var out = new Bytes();
    out.u16(0).u16(response ? 0x8400 : 0).u16(questions).u16(answers).u16(0).u16(0);
    for (byte[] section : sections) {
      out.put(section);
    }
    return out.toByteArray();
  }

  public static byte[] question(byte[] name, int type) {
    return new Bytes().put(name).u16(type).u16(1).toByteArray();
  }

  /** Small big-endian writer. */
  public static final class Bytes {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    public Bytes u8(int value) {
      out.write(value);
      return this;
    }

    public Bytes u16(int value) {
      return u8(value >> 8).u8(value);
    }

    public Bytes u32(long value) {
      return u16((int) (value >> 16)).u16((int) value);
    }

    public Bytes put(byte[] bytes) {
      out.writeBytes(bytes);
      return this;
    }

    public byte[] toByteArray() {
      return out.toByteArray();
    }
  }
}
