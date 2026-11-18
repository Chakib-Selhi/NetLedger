package io.github.chakibselhi.netledger.agent.ui;

import io.github.chakibselhi.netledger.agent.Agent;
import io.github.chakibselhi.netledger.agent.alerts.RecentAlerts;
import java.awt.AWTException;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.Menu;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.RenderingHints;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.image.BufferedImage;
import java.util.EnumMap;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Menu bar icon of the agent (EF-14). Thin AWT layer over {@link MenuModel}. */
public final class TrayMenu {

  private final Supplier<Agent.Status> status;
  private final BooleanSupplier alertsConnected;
  private final RecentAlerts recent;
  private final Consumer<Boolean> pause;
  private final Consumer<String> openDashboard;
  private final Runnable quit;
  private final Map<MenuModel.State, BufferedImage> icons = new EnumMap<>(MenuModel.State.class);

  private final MenuItem server = disabled("…");
  private final MenuItem network = disabled("…");
  private final MenuItem capture = disabled("…");
  private final MenuItem pauseItem = new MenuItem("Pause");
  private Menu alerts = new Menu("Dernières alertes");
  private PopupMenu menu;
  private TrayIcon icon;
  private MenuModel shown;

  public TrayMenu(
      Supplier<Agent.Status> status,
      BooleanSupplier alertsConnected,
      RecentAlerts recent,
      Consumer<Boolean> pause,
      Consumer<String> openDashboard,
      Runnable quit) {
    this.status = status;
    this.alertsConnected = alertsConnected;
    this.recent = recent;
    this.pause = pause;
    this.openDashboard = openDashboard;
    this.quit = quit;
    icons.put(MenuModel.State.ACTIVE, dot(new Color(0x2E, 0xA0, 0x43)));
    icons.put(MenuModel.State.IDLE, dot(new Color(0x8E, 0x8E, 0x93)));
    icons.put(MenuModel.State.SERVER_DOWN, dot(new Color(0xD7, 0x3A, 0x2F)));
  }

  public static boolean supported() {
    return !GraphicsEnvironment.isHeadless() && SystemTray.isSupported();
  }

  public void install() throws AWTException {
    menu = new PopupMenu();
    menu.add(server);
    menu.add(network);
    menu.add(capture);
    menu.addSeparator();
    pauseItem.addActionListener(e -> pause.accept(!status.get().paused()));
    menu.add(pauseItem);
    var dashboard = new MenuItem("Ouvrir le tableau de bord");
    dashboard.addActionListener(e -> openDashboard.accept("/"));
    menu.add(dashboard);
    menu.add(alerts);
    menu.addSeparator();
    var exit = new MenuItem("Quitter NetLedger");
    exit.addActionListener(e -> quit.run());
    menu.add(exit);
    icon = new TrayIcon(icons.get(MenuModel.State.IDLE), "NetLedger", menu);
    icon.setImageAutoSize(true);
    SystemTray.getSystemTray().add(icon);
    var timer = new javax.swing.Timer(2_000, e -> refresh());
    timer.setInitialDelay(0);
    timer.start();
  }

  private void refresh() {
    MenuModel model = MenuModel.of(status.get(), alertsConnected.getAsBoolean(), recent.list());
    if (model.equals(shown)) {
      return;
    }
    shown = model;
    EventQueue.invokeLater(() -> apply(model));
  }

  private void apply(MenuModel model) {
    server.setLabel(model.server());
    network.setLabel(model.network());
    capture.setLabel(model.capture());
    pauseItem.setLabel(model.pauseLabel());
    icon.setImage(icons.get(model.state()));
    icon.setToolTip("NetLedger — " + model.capture());
    var fresh = new Menu("Dernières alertes");
    if (model.alerts().isEmpty()) {
      fresh.add(disabled("Aucune alerte depuis le lancement"));
    }
    for (MenuModel.AlertEntry entry : model.alerts()) {
      var item = new MenuItem(entry.label());
      item.addActionListener(e -> openDashboard.accept(entry.path()));
      fresh.add(item);
    }
    int position = indexOf(alerts);
    menu.insert(fresh, position);
    menu.remove(position + 1);
    alerts = fresh;
  }

  private int indexOf(MenuItem item) {
    for (int i = 0; i < menu.getItemCount(); i++) {
      if (menu.getItem(i) == item) {
        return i;
      }
    }
    throw new IllegalStateException("Alert menu missing");
  }

  private static MenuItem disabled(String label) {
    var item = new MenuItem(label);
    item.setEnabled(false);
    return item;
  }

  private static BufferedImage dot(Color color) {
    var image = new BufferedImage(18, 18, BufferedImage.TYPE_INT_ARGB);
    Graphics2D g = image.createGraphics();
    g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
    g.setColor(color);
    g.fillOval(4, 4, 10, 10);
    g.dispose();
    return image;
  }
}
