package io.github.chakibselhi.netledger.agent.system;

import java.io.IOException;
import java.util.List;

/** Runs a system command and returns its standard output. Abstracted so parsing is testable. */
@FunctionalInterface
public interface CommandRunner {

  /**
   * @throws IOException when the command cannot start, fails or times out
   */
  String run(List<String> command) throws IOException;
}
