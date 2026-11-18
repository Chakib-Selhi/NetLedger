package io.github.chakibselhi.netledger.server.identification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.StringReader;
import java.util.List;
import org.junit.jupiter.api.Test;

class OuiRegistryTest {

  private static final String HEADER =
      "Registry,Assignment,Organization Name,Organization Address\n";

  private static OuiRegistry registry() throws Exception {
    return OuiRegistry.fromCsv(
        List.of(
            new StringReader(
                HEADER
                    + "MA-L,F0B3EC,\"Apple, Inc.\",1 Infinite Loop Cupertino CA US 95014\n"
                    + "MA-L,8C1F64,IEEE Registration Authority,\n"
                    + "MA-L,741AE0,IEEE Registration Authority,\n"
                    + "MA-L,000000,Private,\n"
                    + "garbage line\n"
                    + "MA-L,XYZ123,Bad,\n"),
            new StringReader(HEADER + "MA-M,741AE09,\"Small Vendor \"\"Quoted\"\" Ltd\",addr\n"),
            new StringReader(HEADER + "MA-S,8C1F64AFA,\"DATA ELECTRONIC DEVICES, INC\",addr\n")));
  }

  @Test
  void longestPrefixWins() throws Exception {
    OuiRegistry registry = registry();

    assertThat(registry.vendorOf("f0:b3:ec:12:34:56")).contains("Apple, Inc.");
    assertThat(registry.vendorOf("8c:1f:64:af:a1:23")).contains("DATA ELECTRONIC DEVICES, INC");
    assertThat(registry.vendorOf("8c:1f:64:00:01:23")).contains("IEEE Registration Authority");
    assertThat(registry.vendorOf("74:1a:e0:91:23:45")).contains("Small Vendor \"Quoted\" Ltd");
    assertThat(registry.size()).isEqualTo(6);
  }

  @Test
  void privateUnknownAndRandomizedAddressesHaveNoVendor() throws Exception {
    OuiRegistry registry = registry();

    assertThat(registry.vendorOf("00:00:00:11:22:33")).isEmpty();
    assertThat(registry.vendorOf("00:11:22:33:44:55")).isEmpty();
    assertThat(registry.vendorOf("f2:b3:ec:12:34:56")).as("locally administered").isEmpty();
    assertThat(OuiRegistry.empty().vendorOf("f0:b3:ec:12:34:56")).isEmpty();
  }

  @Test
  void rejectsFilesThatAreNotRegistries() {
    assertThatThrownBy(() -> OuiRegistry.fromCsv(List.of(new StringReader("<html>blocked</html>"))))
        .hasMessageContaining("Not an IEEE registry");
    assertThatThrownBy(() -> OuiRegistry.fromCsv(List.of(new StringReader(""))))
        .hasMessageContaining("Not an IEEE registry");
  }

  @Test
  void splitsQuotedCsvFields() {
    assertThat(OuiRegistry.fields("a,\"b, c\",\"d \"\"e\"\"\","))
        .containsExactly("a", "b, c", "d \"e\"", "");
  }
}
