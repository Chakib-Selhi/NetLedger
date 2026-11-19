package io.github.chakibselhi.netledger.agent.system;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Runs commands without a shell: arguments are passed as an array, so nothing in them is ever
 * interpreted as shell syntax.
 */
public final class ProcessCommandRunner implements CommandRunner {

  private final Duration timeout;

  public ProcessCommandRunner(Duration timeout) {
    this.timeout = timeout;
  }

  @Override
  public String run(List<String> command) throws IOException {
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    try {
      if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
        process.destroyForcibly();
        throw new IOException(command.get(0) + " timed out");
      }
      String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      if (process.exitValue() != 0) {
        String first = output.strip().lines().findFirst().orElse("");
        throw new IOException(
            command.get(0)
                + " exited with "
                + process.exitValue()
                + (first.isEmpty()
                    ? ""
                    : ": " + first.substring(0, Math.min(first.length(), 200))));
      }
      return output;
    } catch (InterruptedException e) {
      process.destroyForcibly();
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while running " + command.get(0), e);
    }
  }
}
