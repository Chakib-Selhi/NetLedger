package io.github.chakibselhi.netledger.core.decode;

import static io.github.chakibselhi.netledger.core.decode.DhcpMessage.OPTION_HOST_NAME;
import static io.github.chakibselhi.netledger.core.decode.DhcpMessage.OPTION_PARAMETER_REQUEST_LIST;
import static io.github.chakibselhi.netledger.core.decode.DhcpMessage.OPTION_REQUESTED_IP;
import static io.github.chakibselhi.netledger.core.decode.DhcpMessage.OPTION_VENDOR_CLASS;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.core.net.MacAddresses;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.StringJoiner;

/**
 * Turns DHCP DISCOVER and REQUEST messages into observations. These are broadcast by the client
 * itself, so any host on the segment sees them, and they carry what identifies the device: host
 * name (option 12), vendor class (option 60) and the parameter request list (option 55), whose
 * order differs between operating systems and serves as a fingerprint.
 */
final class DhcpDecoder {

  private DhcpDecoder() {}

  static Optional<Observation> decode(Instant timestamp, byte[] data, int offset, int length) {
    Optional<DhcpMessage> parsed = DhcpMessage.parse(data, offset, length);
    if (parsed.isEmpty()) {
      return Optional.empty();
    }
    DhcpMessage message = parsed.get();
    int type = message.messageType(data);
    if (type != DhcpMessage.TYPE_DISCOVER && type != DhcpMessage.TYPE_REQUEST) {
      return Optional.empty();
    }
    if (!MacAddresses.isUnicast(data, message.clientMacOffset())) {
      return Optional.empty();
    }
    return Optional.of(
        new Observation(
            timestamp,
            ObservationSource.DHCP,
            MacAddresses.format(data, message.clientMacOffset()),
            clientIp(data, message),
            text(data, message, OPTION_HOST_NAME),
            fingerprint(data, message),
            text(data, message, OPTION_VENDOR_CLASS),
            List.of()));
  }

  /** Requested address (option 50) during DORA, otherwise ciaddr when renewing. */
  private static String clientIp(byte[] data, DhcpMessage message) {
    Optional<DhcpMessage.Option> requested =
        message.option(OPTION_REQUESTED_IP).filter(o -> o.length() == 4);
    if (requested.isPresent()) {
      return PacketLayout.address(data, requested.get().valueOffset(), 4);
    }
    String ciaddr = PacketLayout.address(data, message.clientIpOffset(), 4);
    return "0.0.0.0".equals(ciaddr) ? null : ciaddr;
  }

  private static String fingerprint(byte[] data, DhcpMessage message) {
    return message
        .option(OPTION_PARAMETER_REQUEST_LIST)
        .filter(o -> o.length() > 0)
        .map(
            o -> {
              var codes = new StringJoiner(",");
              for (int i = 0; i < o.length(); i++) {
                codes.add(Integer.toString(data[o.valueOffset() + i] & 0xFF));
              }
              return codes.toString();
            })
        .orElse(null);
  }

  private static String text(byte[] data, DhcpMessage message, int code) {
    return message
        .option(code)
        .map(o -> TextSanitizer.clean(data, o.valueOffset(), o.length()))
        .orElse(null);
  }
}
