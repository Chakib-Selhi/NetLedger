package io.github.chakibselhi.netledger.agent.ui;

import io.github.chakibselhi.netledger.agent.setup.SetupChecks;
import io.github.chakibselhi.netledger.agent.setup.SetupChecks.Check;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

/** Setup assistant: shows each check, what to do when it fails, and the usage rules. */
public final class SetupWindow {

  private static final Color OK = new Color(0x1A, 0x7F, 0x37);
  private static final Color TODO = new Color(0xCF, 0x22, 0x2E);
  private static final Color INFO = new Color(0x6E, 0x6E, 0x73);
  static final String NOTE =
      "NetLedger écoute seulement les réseaux que vous déclarez comme les vôtres ou autorisés par"
          + " leur administrateur, depuis le tableau de bord. Au premier lancement, macOS peut"
          + " demander l'accès au réseau local : il sert à interroger les services mDNS"
          + " (AirPlay, imprimantes) du réseau.";

  private final SetupChecks checks;
  private final boolean blocking;
  private final CompletableFuture<Boolean> outcome = new CompletableFuture<>();
  private final JFrame frame = new JFrame("NetLedger — installation");
  private final JPanel list = new JPanel();
  private final JButton recheck = new JButton("Vérifier de nouveau");
  private final JButton proceed;

  private SetupWindow(SetupChecks checks, boolean blocking) {
    this.checks = checks;
    this.blocking = blocking;
    this.proceed = new JButton(blocking ? "Démarrer NetLedger" : "Fermer");
  }

  /**
   * Shows the assistant and waits until the required checks pass and the user starts the agent.
   *
   * @return false when the user quits instead
   */
  public static boolean awaitReady(SetupChecks checks, List<Check> initial) {
    var window = new SetupWindow(checks, true);
    SwingUtilities.invokeLater(() -> window.open(initial));
    return window.outcome.join();
  }

  /** Opened from the menu bar while the agent runs. */
  public static void show(SetupChecks checks) {
    var window = new SetupWindow(checks, false);
    SwingUtilities.invokeLater(
        () -> {
          window.open(List.of());
          window.refresh();
        });
  }

  private void open(List<Check> initial) {
    list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
    var note = text(NOTE, INFO);
    note.setBorder(BorderFactory.createEmptyBorder(12, 0, 0, 0));

    recheck.addActionListener(e -> refresh());
    proceed.addActionListener(
        e -> {
          outcome.complete(true);
          frame.dispose();
        });
    var buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    if (blocking) {
      var quit = new JButton("Quitter");
      quit.addActionListener(e -> close());
      buttons.add(quit);
    }
    buttons.add(recheck);
    buttons.add(proceed);

    var content = new JPanel(new BorderLayout());
    content.setBorder(BorderFactory.createEmptyBorder(16, 18, 12, 18));
    content.add(list, BorderLayout.NORTH);
    content.add(note, BorderLayout.CENTER);
    content.add(buttons, BorderLayout.SOUTH);

    frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
    frame.addWindowListener(
        new WindowAdapter() {
          @Override
          public void windowClosing(WindowEvent e) {
            close();
          }
        });
    frame.setContentPane(content);
    show(initial);
    frame.setMinimumSize(new Dimension(560, 360));
    frame.setLocationRelativeTo(null);
    frame.setVisible(true);
    frame.toFront();
  }

  private void close() {
    outcome.complete(false);
    frame.dispose();
  }

  /** Checks call the server with a timeout: run them off the event thread. */
  private void refresh() {
    recheck.setEnabled(false);
    Thread.ofVirtual()
        .start(
            () -> {
              List<Check> result = checks.run();
              SwingUtilities.invokeLater(
                  () -> {
                    show(result);
                    recheck.setEnabled(true);
                  });
            });
  }

  private void show(List<Check> result) {
    list.removeAll();
    for (Check c : result) {
      list.add(row(c));
      list.add(Box.createVerticalStrut(10));
    }
    proceed.setEnabled(!blocking || (!result.isEmpty() && SetupChecks.ready(result)));
    frame.pack();
  }

  private static JPanel row(Check c) {
    var row = new JPanel();
    row.setLayout(new BoxLayout(row, BoxLayout.Y_AXIS));
    row.setAlignmentX(Component.LEFT_ALIGNMENT);
    String state = c.ok() ? "OK" : c.required() ? "À faire" : "À vérifier";
    var title = new JLabel(state + " — " + c.title());
    title.setFont(title.getFont().deriveFont(Font.BOLD));
    title.setForeground(c.ok() ? OK : c.required() ? TODO : INFO);
    row.add(title);
    row.add(text(c.detail(), null));
    if (c.fix() != null) {
      // A selectable field, so the command can be copied into the Terminal.
      var fix = new JTextField(c.fix());
      fix.setEditable(false);
      fix.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
      fix.setAlignmentX(Component.LEFT_ALIGNMENT);
      row.add(fix);
    }
    return row;
  }

  private static JTextArea text(String value, Color color) {
    var area = new JTextArea(value);
    area.setEditable(false);
    area.setLineWrap(true);
    area.setWrapStyleWord(true);
    area.setOpaque(false);
    area.setColumns(48);
    area.setAlignmentX(Component.LEFT_ALIGNMENT);
    if (color != null) {
      area.setForeground(color);
    }
    return area;
  }
}
