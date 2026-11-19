package io.github.chakibselhi.netledger.agent;

import io.github.chakibselhi.netledger.agent.alerts.AlertStreamClient;
import io.github.chakibselhi.netledger.agent.alerts.OsascriptNotifier;
import io.github.chakibselhi.netledger.agent.alerts.RecentAlerts;
import io.github.chakibselhi.netledger.agent.buffer.ObservationBuffer;
import io.github.chakibselhi.netledger.agent.capture.CaptureSession;
import io.github.chakibselhi.netledger.agent.capture.PcapPacketSource;
import io.github.chakibselhi.netledger.agent.config.AgentConfig;
import io.github.chakibselhi.netledger.agent.config.KeychainTokenStore;
import io.github.chakibselhi.netledger.agent.mdns.MdnsQuerier;
import io.github.chakibselhi.netledger.agent.network.NetworkDetector;
import io.github.chakibselhi.netledger.agent.scan.ArpScanner;
import io.github.chakibselhi.netledger.agent.scan.PcapFrameSender;
import io.github.chakibselhi.netledger.agent.server.ServerClient;
import io.github.chakibselhi.netledger.agent.setup.LocalNetworkAccess;
import io.github.chakibselhi.netledger.agent.setup.SetupChecks;
import io.github.chakibselhi.netledger.agent.system.CommandRunner;
import io.github.chakibselhi.netledger.agent.system.ProcessCommandRunner;
import io.github.chakibselhi.netledger.agent.ui.SetupWindow;
import io.github.chakibselhi.netledger.agent.ui.TrayMenu;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Entry point of the agent: setup checks, then capture, alerts and the menu bar icon. */
public final class AgentMain {

  private static final Logger log = LoggerFactory.getLogger(AgentMain.class);

  private AgentMain() {}

  public static void main(String[] args) throws Exception {
    // A menu bar agent: no Dock icon, no application menu.
    System.setProperty("apple.awt.UIElement", "true");
    Path configFile = args.length > 0 ? Path.of(args[0]) : AgentConfig.defaultFile();
    AgentConfig config = AgentConfig.load(configFile);
    var commands = new ProcessCommandRunner(Duration.ofSeconds(5));
    var keychain = new KeychainTokenStore(commands);
    var localNetwork =
        new LocalNetworkAccess(
            new LocalNetworkAccess.Probe() {
              @Override
              public Optional<String> gateway() throws IOException {
                return NetworkDetector.parseGateway(
                    commands.run(List.of("route", "-n", "get", "default")));
              }

              @Override
              public String arpEntry(String gateway) {
                try {
                  return commands.run(List.of("arp", "-n", gateway));
                } catch (IOException e) {
                  return String.valueOf(e.getMessage());
                }
              }
            },
            () -> new MdnsQuerier().queryServiceTypes("0.0.0.0"));
    var setup =
        new SetupChecks(
            () -> Files.isReadable(Path.of("/dev/bpf0")),
            localNetwork::state,
            () -> {
              try {
                localNetwork.request();
              } catch (IOException e) {
                log.warn("Local network request failed: {}", e.getMessage());
              }
            },
            keychain::read,
            t -> new ServerClient(config.serverUrl(), t, Duration.ofSeconds(3)).health());
    List<SetupChecks.Check> checks = setup.run();
    if (!SetupChecks.ready(checks)) {
      if (!TrayMenu.supported()) {
        throw new IllegalStateException("Setup incomplete: " + checks);
      }
      if (!SetupWindow.awaitReady(setup, checks)) {
        System.exit(0);
      }
    }
    String token =
        keychain.read().orElseThrow(() -> new IllegalStateException("No token in the keychain"));

    var server = new ServerClient(config.serverUrl(), token, Duration.ofSeconds(10));
    var detector =
        new NetworkDetector(
            commands, NetworkDetector::javaInterfaceLookup, config.interfaceOverride());
    var buffer = new ObservationBuffer(config.bufferCapacity(), config.dedupWindow());
    var querier = new MdnsQuerier();
    var scanner = new ArpScanner(new PcapFrameSender());
    var agent =
        new Agent(
            config,
            detector::detect,
            server,
            buffer,
            (network, networkId, target) ->
                new CaptureSession(
                        new PcapPacketSource(network.interfaceName()),
                        networkId,
                        target,
                        network.interfaceName())
                    .start(),
            (network, decision) -> {
              querier.queryServiceTypes(network.localIp());
              querier.queryIdentifyingInstances(network.localIp());
            },
            (network, decision) -> {
              byte[] localMac =
                  java.net.NetworkInterface.getByName(network.interfaceName()).getHardwareAddress();
              int sent = scanner.scan(network, localMac);
              log.info("ARP sweep: {} request(s) sent on {}", sent, network.subnet());
            },
            Clock.systemUTC());

    var recent = new RecentAlerts(5);
    var notifier = new OsascriptNotifier(commands, ZoneId.systemDefault());
    var alerts =
        new AlertStreamClient(
                config.serverUrl(),
                token,
                alert -> {
                  log.info("Alert {}: {} — {}", alert.kind(), alert.title(), alert.message());
                  recent.add(alert);
                  notifier.accept(alert);
                })
            .start();
    if (TrayMenu.supported()) {
      new TrayMenu(
              agent::status,
              alerts::connected,
              recent,
              agent::setPaused,
              path -> open(config.serverUrl(), path, commands),
              () -> SetupWindow.show(setup),
              AgentMain::quit)
          .install();
    } else {
      log.info("No menu bar available: running headless");
    }
    log.info("NetLedger agent started; server {}", config.serverUrl());
    var scheduler =
        Executors.newSingleThreadScheduledExecutor(
            r -> Thread.ofPlatform().name("agent").unstarted(r));
    scheduler.scheduleWithFixedDelay(
        () -> {
          try {
            agent.tick();
          } catch (RuntimeException e) {
            log.error("Agent step failed", e);
          }
        },
        0,
        config.tickInterval().toMillis(),
        TimeUnit.MILLISECONDS);
    scheduler.scheduleWithFixedDelay(
        () -> log.info("{}", describe(agent.status())), 1, 1, TimeUnit.MINUTES);
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  scheduler.shutdownNow();
                  agent.shutdown();
                  log.info("NetLedger agent stopped");
                }));
    Thread.currentThread().join();
  }

  /** Opens a dashboard page in the default browser; only paths of the configured server. */
  static void open(URI server, String path, CommandRunner commands) {
    String base = server.toString().replaceAll("/+$", "");
    try {
      commands.run(List.of("open", base + path));
    } catch (IOException e) {
      log.warn("Cannot open the dashboard: {}", e.getMessage());
    }
  }

  /** Quitting runs the shutdown hook, which stops capture and sends what is left. */
  private static void quit() {
    // Called on the AWT event thread: exiting from another thread lets the hook run unhindered.
    Thread.ofPlatform().start(() -> System.exit(0));
  }

  static String describe(Agent.Status s) {
    String network = s.network() == null ? "offline" : s.network().subnet();
    String trust = s.decision() == null ? "?" : s.decision().trust();
    return "network=%s trust=%s capturing=%s buffered=%d sent=%d dropped=%d server=%s"
        .formatted(
            network,
            trust,
            s.capturing(),
            s.buffered(),
            s.sent(),
            s.dropped(),
            s.serverReachable() ? "up" : "down");
  }
}
