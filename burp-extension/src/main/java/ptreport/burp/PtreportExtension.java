package ptreport.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

/** Burp extension: send requests and responses to a local ptreport instance. */
public final class PtreportExtension implements BurpExtension {
    static final String NAME = "ptreport";

    @Override
    public void initialize(MontoyaApi montoya) {
        montoya.extension().setName(NAME);
        Settings settings = new Settings(montoya.persistence().preferences());
        ApiClient api = new ApiClient(settings);
        Consumer<String> log = montoya.logging()::logToOutput;

        SettingsTab tab = new SettingsTab(settings, api, log);
        montoya.userInterface().applyThemeToComponent(tab);
        montoya.userInterface().registerSuiteTab(NAME, tab);

        montoya.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<HttpRequestResponse> selected = new ArrayList<>();
                event.messageEditorRequestResponse().ifPresent(e -> selected.add(e.requestResponse()));
                if (selected.isEmpty()) {
                    selected.addAll(event.selectedRequestResponses());
                }
                if (selected.isEmpty()) {
                    return List.of();
                }
                String label = selected.size() == 1 ? "Send to ptreport ..." : "Send " + selected.size() + " requests to ptreport ...";
                JMenuItem item = new JMenuItem(label);
                item.addActionListener(e -> open(montoya, settings, api, selected, log));
                return List.of(item);
            }
        });
        log.accept("ptreport extension loaded. Server: " + settings.baseUrl()
                + (settings.configured() ? "" : " (set the API token in the ptreport tab)"));
    }

    private static void open(MontoyaApi montoya, Settings settings, ApiClient api, List<HttpRequestResponse> selected,
                             Consumer<String> log) {
        SwingUtilities.invokeLater(() -> {
            java.awt.Frame frame = montoya.userInterface().swingUtils().suiteFrame();
            if (!settings.configured()) {
                JOptionPane.showMessageDialog(frame,
                        "Set the ptreport API token first (the \"ptreport\" tab in Burp).\n"
                                + "Find it in ptreport under Settings -> API, or run: ptreport --show-api-token",
                        NAME, JOptionPane.WARNING_MESSAGE);
                return;
            }
            List<Message> messages = new ArrayList<>();
            for (HttpRequestResponse rr : selected) {
                if (rr != null && rr.request() != null) {
                    messages.add(Message.of(rr));
                }
            }
            if (messages.isEmpty()) {
                return;
            }
            SendDialog dialog = new SendDialog(frame, api, settings, messages, log);
            montoya.userInterface().applyThemeToComponent(dialog);
            dialog.setVisible(true);
        });
    }
}
