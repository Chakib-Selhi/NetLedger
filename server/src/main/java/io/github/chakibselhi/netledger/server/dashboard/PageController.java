package io.github.chakibselhi.netledger.server.dashboard;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * The dashboard is one page whose script draws the view from the address. These are the addresses
 * the agent opens from a notification or the menu bar.
 */
@Controller
class PageController {

  @GetMapping({"/", "/networks", "/networks/{id:\\d+}", "/devices/{id:\\d+}", "/events"})
  String page() {
    return "forward:/index.html";
  }
}
