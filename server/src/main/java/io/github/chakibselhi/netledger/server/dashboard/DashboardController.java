package io.github.chakibselhi.netledger.server.dashboard;

import io.github.chakibselhi.netledger.server.correlation.DeviceCommands;
import io.github.chakibselhi.netledger.server.dashboard.DashboardQueries.DeviceView;
import io.github.chakibselhi.netledger.server.dashboard.DashboardQueries.EventView;
import io.github.chakibselhi.netledger.server.dashboard.DashboardQueries.IpView;
import io.github.chakibselhi.netledger.server.dashboard.DashboardQueries.NetworkView;
import io.github.chakibselhi.netledger.server.dashboard.DashboardQueries.ObservationView;
import io.github.chakibselhi.netledger.server.dashboard.DashboardQueries.ServiceView;
import io.github.chakibselhi.netledger.server.network.NetworkService;
import io.github.chakibselhi.netledger.server.network.Trust;
import io.github.chakibselhi.netledger.server.persistence.Timestamps;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** JSON behind the dashboard pages (EF-15, EF-16). Changes require the CSRF token. */
@RestController
@RequestMapping("/ui")
class DashboardController {

  static final int MAX_EVENTS = 500;
  static final int OBSERVATIONS_SHOWN = 100;

  record CsrfView(String headerName, String token) {}

  /** {@code null} fields are left unchanged. */
  record NetworkChange(String label, String trust) {}

  /** {@code null} fields are left unchanged; an empty name or category clears it. */
  record DeviceChange(String displayName, String category, String status) {}

  record MergeRequest(Long into) {}

  record DeviceDetail(
      DeviceView device,
      NetworkView network,
      List<IpView> ips,
      List<ServiceView> services,
      List<ObservationView> observations,
      List<EventView> events,
      List<DeviceView> mergeCandidates) {}

  private final DashboardQueries queries;
  private final NetworkService networks;
  private final DeviceCommands devices;
  private final Clock clock;

  DashboardController(
      DashboardQueries queries, NetworkService networks, DeviceCommands devices, Clock clock) {
    this.queries = queries;
    this.networks = networks;
    this.devices = devices;
    this.clock = clock;
  }

  /** The page reads the token here; a hostile site cannot, the same-origin policy forbids it. */
  @GetMapping("/csrf")
  CsrfView csrf(CsrfToken token) {
    return new CsrfView(token.getHeaderName(), token.getToken());
  }

  @GetMapping("/networks")
  List<NetworkView> networks() {
    return queries.networks();
  }

  @GetMapping("/networks/{id}")
  NetworkView network(@PathVariable long id) {
    return requireNetwork(id);
  }

  @PatchMapping("/networks/{id}")
  NetworkView changeNetwork(@PathVariable long id, @RequestBody NetworkChange change) {
    requireNetwork(id);
    if (change.label() != null) {
      networks.rename(id, DeviceCommands.text(change.label(), DeviceCommands.MAX_NAME, "label"));
    }
    if (change.trust() != null) {
      networks.changeTrust(id, Trust.fromValue(change.trust()));
    }
    return requireNetwork(id);
  }

  @DeleteMapping("/networks/{id}")
  ResponseEntity<Void> deleteNetwork(@PathVariable long id) {
    devices.deleteNetwork(id);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/networks/{id}/devices")
  List<DeviceView> devices(@PathVariable long id) {
    requireNetwork(id);
    return queries.devices(id);
  }

  @GetMapping("/networks/{id}/inventory.csv")
  ResponseEntity<String> exportCsv(@PathVariable long id) {
    requireNetwork(id);
    return attachment(
        "netledger-network-" + id + ".csv",
        new MediaType("text", "csv", java.nio.charset.StandardCharsets.UTF_8),
        InventoryExport.csv(queries.devices(id)));
  }

  @GetMapping("/networks/{id}/inventory.json")
  ResponseEntity<Map<String, Object>> exportJson(@PathVariable long id) {
    NetworkView network = requireNetwork(id);
    List<Map<String, Object>> list =
        queries.devices(id).stream()
            .map(
                d ->
                    Map.<String, Object>of(
                        "device", d,
                        "ips", queries.ips(d.id()),
                        "services", queries.services(d.id())))
            .toList();
    Map<String, Object> body =
        Map.of(
            "exportedAt", Timestamps.format(clock.instant()), "network", network, "devices", list);
    return ResponseEntity.ok()
        .header(
            HttpHeaders.CONTENT_DISPOSITION,
            "attachment; filename=\"netledger-network-" + id + ".json\"")
        .contentType(MediaType.APPLICATION_JSON)
        .body(body);
  }

  @GetMapping("/devices/{id}")
  DeviceDetail device(@PathVariable long id) {
    DeviceView device = requireDevice(id);
    return new DeviceDetail(
        device,
        requireNetwork(device.networkId()),
        queries.ips(id),
        queries.services(id),
        queries.observations(id, OBSERVATIONS_SHOWN),
        queries.events(null, id, 50),
        queries.devices(device.networkId()).stream().filter(d -> d.id() != id).toList());
  }

  @PatchMapping("/devices/{id}")
  DeviceView changeDevice(@PathVariable long id, @RequestBody DeviceChange change) {
    devices.update(id, change.displayName(), change.category(), change.status());
    return requireDevice(id);
  }

  /** Merges this device into {@code into}; the answer is the remaining device. */
  @PostMapping("/devices/{id}/merge")
  DeviceView merge(@PathVariable long id, @RequestBody MergeRequest request) {
    if (request.into() == null) {
      throw new IllegalArgumentException("into is required");
    }
    return requireDevice(devices.merge(id, request.into()));
  }

  @GetMapping("/events")
  List<EventView> events(
      @RequestParam(required = false) Long network, @RequestParam(defaultValue = "200") int limit) {
    return queries.events(network, null, Math.clamp(limit, 1, MAX_EVENTS));
  }

  private NetworkView requireNetwork(long id) {
    return queries.network(id).orElseThrow(() -> new NoSuchElementException("Unknown network"));
  }

  private DeviceView requireDevice(long id) {
    return queries.device(id).orElseThrow(() -> new NoSuchElementException("Unknown device"));
  }

  private static ResponseEntity<String> attachment(String name, MediaType type, String body) {
    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + name + "\"")
        .contentType(type)
        .body(body);
  }
}
