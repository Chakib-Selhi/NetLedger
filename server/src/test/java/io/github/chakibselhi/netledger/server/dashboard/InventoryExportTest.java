package io.github.chakibselhi.netledger.server.dashboard;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class InventoryExportTest {

  @Test
  void quotesEveryCellAndDoublesQuotes() {
    assertThat(InventoryExport.cell(null)).isEmpty();
    assertThat(InventoryExport.cell("")).isEqualTo("\"\"");
    assertThat(InventoryExport.cell("Salon, \"TV\"")).isEqualTo("\"Salon, \"\"TV\"\"\"");
  }

  @Test
  void neutralizesWhatASpreadsheetWouldRunAsAFormula() {
    for (String hostile : new String[] {"=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"}) {
      assertThat(InventoryExport.cell(hostile)).startsWith("\"'");
    }
    assertThat(InventoryExport.cell("a=1")).isEqualTo("\"a=1\"");
  }
}
