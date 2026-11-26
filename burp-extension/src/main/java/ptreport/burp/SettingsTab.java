package ptreport.burp;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingWorker;

/** The "ptreport" tab in Burp: server URL, API token, connection test. */
final class SettingsTab extends JPanel {
    private final Settings settings;
    private final ApiClient api;
    private final JTextField url = new JTextField(36);
    private final JPasswordField token = new JPasswordField(36);
    private final JLabel status = new JLabel(" ");

    SettingsTab(Settings settings, ApiClient api, Consumer<String> log) {
        super(new BorderLayout());
        this.settings = settings;
        this.api = api;
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 4, 6, 4);
        c.anchor = GridBagConstraints.WEST;

        JLabel heading = new JLabel("ptreport");
        heading.setFont(heading.getFont().deriveFont(java.awt.Font.BOLD, heading.getFont().getSize2D() * 1.5f));
        JTextArea intro = new JTextArea("Right-click a request or response anywhere in Burp (Proxy history, Repeater, "
                + "Target, Logger ...) and choose \"Send to ptreport ...\" to add it as HTTP evidence to a new or "
                + "existing finding.", 2, 60);
        intro.setEditable(false);
        intro.setFocusable(false);
        intro.setOpaque(false);
        intro.setLineWrap(true);
        intro.setWrapStyleWord(true);
        intro.setBorder(BorderFactory.createEmptyBorder());
        intro.setMargin(new Insets(0, 0, 0, 0));
        intro.setFont(heading.getFont().deriveFont(java.awt.Font.PLAIN, heading.getFont().getSize2D() / 1.5f));
        JPanel head = new JPanel(new BorderLayout(0, 6));
        head.add(heading, BorderLayout.NORTH);
        head.add(intro, BorderLayout.CENTER);
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        form.add(head, c);
        c.gridwidth = 1;
        c.fill = GridBagConstraints.NONE;

        url.setText(settings.baseUrl());
        token.setText(settings.token());
        row(form, c, 1, "ptreport URL", url, "Default " + Settings.DEFAULT_URL + " (ptreport listens on this machine only).");
        row(form, c, 2, "API token", token, "In ptreport: Settings -> API, or run: ptreport --show-api-token");

        JButton save = new JButton("Save");
        JButton test = new JButton("Test connection");
        save.addActionListener(e -> {
            settings.save(url.getText(), new String(token.getPassword()));
            url.setText(settings.baseUrl());
            status.setText("Saved.");
            log.accept("Settings saved (" + settings.baseUrl() + ")");
        });
        test.addActionListener(e -> {
            settings.save(url.getText(), new String(token.getPassword()));
            test(test);
        });
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        buttons.add(save);
        buttons.add(javax.swing.Box.createHorizontalStrut(8));
        buttons.add(test);
        c.gridx = 1;
        c.gridy = 3;
        form.add(buttons, c);
        c.gridy = 4;
        form.add(status, c);

        JPanel wrap = new JPanel(new BorderLayout());
        wrap.add(form, BorderLayout.NORTH);
        add(wrap, BorderLayout.WEST);
    }

    private static void row(JPanel form, GridBagConstraints c, int y, String label, JTextField field, String hint) {
        c.gridy = y;
        c.gridx = 0;
        JLabel l = new JLabel(label);
        l.setLabelFor(field);
        form.add(l, c);
        c.gridx = 1;
        JPanel p = new JPanel(new BorderLayout(0, 2));
        p.add(field, BorderLayout.NORTH);
        JLabel h = new JLabel(hint);
        h.setEnabled(false);
        p.add(h, BorderLayout.SOUTH);
        form.add(p, c);
    }

    private void test(JButton button) {
        button.setEnabled(false);
        status.setText("Connecting ...");
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    String version = api.ping();
                    int reports = api.reports().size();
                    return "Connected to ptreport " + version + " (" + reports + " report(s)).";
                } catch (ApiClient.ApiException e) {
                    return e.describe();
                }
            }

            @Override
            protected void done() {
                try {
                    status.setText(SendDialog.plain(get()));
                } catch (Exception e) {
                    status.setText(SendDialog.plain(String.valueOf(e.getMessage())));
                }
                button.setEnabled(true);
            }
        }.execute();
    }
}
