package ptreport.burp;

import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.KeyEvent;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/** "Send to ptreport": pick the report, a new or existing finding, title, CWE, severity and target. */
final class SendDialog extends JDialog {
    private static final String[][] SEVERITIES = {
        {"critical", "Critical"}, {"high", "High"}, {"medium", "Medium"}, {"low", "Low"}, {"info", "Informational"},
    };
    private static final int CWE_RESULTS = 200;
    /** Shown first while the search box is empty: the weaknesses most often reported in pentests. */
    private static final List<String> COMMON_CWES = List.of(
            "CWE-79", "CWE-89", "CWE-639", "CWE-352", "CWE-918", "CWE-22", "CWE-78", "CWE-611", "CWE-434",
            "CWE-287", "CWE-307", "CWE-384", "CWE-613", "CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-200",
            "CWE-209", "CWE-532", "CWE-601", "CWE-1021", "CWE-693", "CWE-614", "CWE-1004", "CWE-326", "CWE-327",
            "CWE-319", "CWE-521", "CWE-798", "CWE-94", "CWE-502", "CWE-1104", "CWE-942", "CWE-16");

    /** Pentest shorthand that does not appear in CWE names, mapped to the CWE it usually means. */
    private static final Map<String, String> CWE_ALIASES = Map.ofEntries(
            Map.entry("xss", "CWE-79"), Map.entry("sqli", "CWE-89"), Map.entry("sql", "CWE-89"),
            Map.entry("idor", "CWE-639"), Map.entry("bola", "CWE-639"), Map.entry("csrf", "CWE-352"),
            Map.entry("xsrf", "CWE-352"), Map.entry("ssrf", "CWE-918"), Map.entry("lfi", "CWE-22"),
            Map.entry("traversal", "CWE-22"), Map.entry("rce", "CWE-78"), Map.entry("cmdi", "CWE-78"),
            Map.entry("xxe", "CWE-611"), Map.entry("upload", "CWE-434"), Map.entry("redirect", "CWE-601"),
            Map.entry("clickjacking", "CWE-1021"), Map.entry("deserialization", "CWE-502"),
            Map.entry("cors", "CWE-942"), Map.entry("ssti", "CWE-1336"), Map.entry("jwt", "CWE-347"));

    /** A combo entry: an id with a label. */
    private record Item(long id, String label, Map<String, Object> data) {
        @Override
        public String toString() {
            return plain(label);
        }
    }

    private final ApiClient api;
    private final Settings settings;
    private final List<Message> messages;
    private final Consumer<String> log;

    private final JComboBox<Item> report = new JComboBox<>();
    private final JRadioButton modeNew = new JRadioButton("New finding", true);
    private final JRadioButton modeExisting = new JRadioButton("Add to an existing finding");
    private final JComboBox<Item> existing = new JComboBox<>();
    private final JTextField title = new JTextField(40);
    private final JTextField cweSearch = new JTextField(40);
    private final DefaultListModel<Cwe> cweModel = new DefaultListModel<>();
    private final JList<Cwe> cweList = new JList<>(cweModel);
    private final JLabel cweChosen = new JLabel("No CWE selected");
    private final JComboBox<String> severity = new JComboBox<>();
    private final JComboBox<Item> target = new JComboBox<>();
    private final JTextField evidenceTitle = new JTextField(40);
    private final JCheckBox includeResponse = new JCheckBox("Include the response");
    private final JLabel status = new JLabel(" ");
    private final JButton send = new JButton("Send to ptreport");
    private static final String LABEL_KEY = "ptreport.label";
    private final List<JComponent> newOnly = new ArrayList<>();

    private List<String[]> allCwes = List.of();
    private String chosenCwe = "";

    SendDialog(Frame owner, ApiClient api, Settings settings, List<Message> messages, Consumer<String> log) {
        super(owner, "Send to ptreport", true);
        this.api = api;
        this.settings = settings;
        this.messages = messages;
        this.log = log;
        build();
        loadReports();
        loadCwes();
    }

    // -------------------------------------------------------------------- layout

    private void build() {
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(12, 12, 4, 12));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        int row = 0;

        Message first = messages.get(0);
        JLabel summary = new JLabel(plain(messages.size() == 1
                ? first.defaultTitle() + "   " + first.origin()
                : messages.size() + " requests will be added as HTTP evidence"));
        summary.setFont(summary.getFont().deriveFont(java.awt.Font.BOLD));
        add(form, c, row++, null, summary);

        report.addActionListener(e -> onReportChanged());
        add(form, c, row++, "Report", report);

        ButtonGroup g = new ButtonGroup();
        g.add(modeNew);
        g.add(modeExisting);
        JPanel modes = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        modes.add(modeNew);
        modes.add(javax.swing.Box.createHorizontalStrut(16));
        modes.add(modeExisting);
        modeNew.addActionListener(e -> updateMode());
        modeExisting.addActionListener(e -> updateMode());
        add(form, c, row++, null, modes);
        add(form, c, row++, "Finding", existing).setVisible(false);

        newOnly.add(add(form, c, row++, "Title *", title));

        cweSearch.putClientProperty("JTextField.placeholderText", "Search: 79, xss, injection ...");
        cweSearch.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filterCwes(); }
            public void removeUpdate(DocumentEvent e) { filterCwes(); }
            public void changedUpdate(DocumentEvent e) { filterCwes(); }
        });
        cweList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        cweList.setVisibleRowCount(7);
        cweList.addListSelectionListener(e -> {
            Cwe sel = cweList.getSelectedValue();
            if (sel != null) {
                String[] v = sel.value();
                chosenCwe = v[0];
                cweChosen.setText(plain("Selected: " + v[0] + " " + v[1]));
                cweChosen.setToolTipText(plain(v[0] + " " + v[1]));
            }
        });
        JButton clearCwe = new JButton("Clear");
        clearCwe.addActionListener(e -> {
            chosenCwe = "";
            cweList.clearSelection();
            cweChosen.setText("No CWE selected");
            cweChosen.setToolTipText(null);
        });
        JPanel cwePanel = new JPanel(new BorderLayout(0, 4));
        JPanel searchRow = new JPanel(new BorderLayout(6, 0));
        searchRow.add(new JLabel("Search"), BorderLayout.WEST);
        searchRow.add(cweSearch, BorderLayout.CENTER);
        cweSearch.setToolTipText("CWE number, name or keyword, e.g. 79, xss, injection");
        cwePanel.add(searchRow, BorderLayout.NORTH);
        JScrollPane cweScroll = new JScrollPane(cweList, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        // Fixed sizes: long CWE names must not push the form wider than the dialog (GridBagLayout would then fall
        // back to minimum sizes and collapse the list).
        cweScroll.setPreferredSize(new Dimension(520, 150));
        cweScroll.setMinimumSize(new Dimension(320, 150));
        cweChosen.setPreferredSize(new Dimension(200, cweChosen.getPreferredSize().height));
        cweChosen.setMinimumSize(new Dimension(0, cweChosen.getPreferredSize().height));
        cwePanel.add(cweScroll, BorderLayout.CENTER);
        JPanel chosenRow = new JPanel(new BorderLayout(8, 0));
        chosenRow.add(cweChosen, BorderLayout.CENTER);
        chosenRow.add(clearCwe, BorderLayout.EAST);
        cwePanel.add(chosenRow, BorderLayout.SOUTH);
        newOnly.add(add(form, c, row++, "CWE", cwePanel));

        DefaultComboBoxModel<String> sev = new DefaultComboBoxModel<>();
        for (String[] s : SEVERITIES) {
            sev.addElement(s[1]);
        }
        severity.setModel(sev);
        severity.setSelectedIndex(2);
        newOnly.add(add(form, c, row++, "Severity *", severity));
        newOnly.add(add(form, c, row++, "Target", target));

        evidenceTitle.setText(messages.size() == 1 ? first.defaultTitle() : "");
        evidenceTitle.putClientProperty("JTextField.placeholderText",
                messages.size() == 1 ? "" : "Empty = method and path of each request");
        add(form, c, row++, "Evidence title", evidenceTitle);
        boolean anyResponse = messages.stream().anyMatch(m -> !m.response().isEmpty());
        includeResponse.setSelected(anyResponse && settings.includeResponse());
        includeResponse.setEnabled(anyResponse);
        add(form, c, row++, null, includeResponse);

        status.setForeground(new java.awt.Color(0xC0392B));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(e -> dispose());
        send.addActionListener(e -> submit());
        buttons.add(cancel);
        buttons.add(send);
        JPanel south = new JPanel(new BorderLayout());
        south.setBorder(BorderFactory.createEmptyBorder(0, 16, 8, 8));
        south.add(status, BorderLayout.CENTER);
        south.add(buttons, BorderLayout.EAST);

        setLayout(new BorderLayout());
        JPanel top = new JPanel(new BorderLayout());
        top.add(form, BorderLayout.NORTH); // rows stay at the top when the mode hides some of them
        add(top, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);
        getRootPane().setDefaultButton(send);
        getRootPane().registerKeyboardAction(e -> dispose(), KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
        send.setEnabled(false);
        updateMode();
        pack();
        setMinimumSize(new Dimension(getWidth(), 0)); // height follows the mode (pack in updateMode)
        setLocationRelativeTo(getOwner());
    }

    private static JComponent add(JPanel form, GridBagConstraints c, int row, String label, JComponent field) {
        c.gridy = row;
        if (label != null) {
            c.gridx = 0;
            c.weightx = 0;
            c.gridwidth = 1;
            JLabel l = new JLabel(label);
            l.setLabelFor(field);
            form.add(l, c);
            field.putClientProperty(LABEL_KEY, l);
            c.gridx = 1;
            c.weightx = 1;
        } else {
            c.gridx = 0;
            c.gridwidth = 2;
            c.weightx = 1;
        }
        form.add(field, c);
        c.gridwidth = 1;
        return field;
    }

    /**
     * Shows only the rows that apply to the chosen mode. Hidden rather than disabled: Burp's theme draws disabled
     * fields almost like enabled ones, which made it look as if title, CWE and severity were still used.
     */
    private void updateMode() {
        boolean isNew = modeNew.isSelected();
        showRow(existing, !isNew);
        for (JComponent comp : newOnly) {
            showRow(comp, isNew);
        }
        if (isDisplayable()) {
            revalidate();
            pack();
        }
        if (isNew) {
            title.requestFocusInWindow();
        }
    }

    private static void showRow(JComponent field, boolean visible) {
        field.setVisible(visible);
        if (field.getClientProperty(LABEL_KEY) instanceof java.awt.Component label) {
            label.setVisible(visible);
        }
    }

    // --------------------------------------------------------------------- data

    private void loadReports() {
        status.setText("Loading reports ...");
        background(api::reports, rows -> {
            DefaultComboBoxModel<Item> m = new DefaultComboBoxModel<>();
            Item select = null;
            for (Map<String, Object> r : rows) {
                String client = Json.str(r, "client_name");
                Item it = new Item(Json.num(r, "id"), Json.str(r, "title") + (client.isEmpty() ? "" : "  (" + client + ")"), r);
                m.addElement(it);
                if (it.id() == settings.lastReport()) {
                    select = it;
                }
            }
            report.setModel(m);
            if (select != null) {
                report.setSelectedItem(select);
            }
            if (rows.isEmpty()) {
                status.setText("ptreport has no reports yet. Create one in ptreport first.");
            } else {
                status.setText(" ");
                onReportChanged();
            }
        });
    }

    private void onReportChanged() {
        Item r = (Item) report.getSelectedItem();
        if (r == null) {
            return;
        }
        send.setEnabled(false);
        long id = r.id();
        background(() -> new Object[] {api.findings(id), api.targets(id)}, res -> {
            if (report.getSelectedItem() != r) {
                return;
            }
            @SuppressWarnings("unchecked") List<Map<String, Object>> findings = (List<Map<String, Object>>) res[0];
            @SuppressWarnings("unchecked") List<Map<String, Object>> targets = (List<Map<String, Object>>) res[1];
            DefaultComboBoxModel<Item> fm = new DefaultComboBoxModel<>();
            for (Map<String, Object> f : findings) {
                fm.addElement(new Item(Json.num(f, "id"), Json.str(f, "display_id") + "  " + Json.str(f, "title"), f));
            }
            existing.setModel(fm);
            modeExisting.setEnabled(!findings.isEmpty());
            if (findings.isEmpty()) {
                modeNew.setSelected(true);
            }
            fillTargets(targets);
            updateMode();
            send.setEnabled(true);
        });
    }

    private void fillTargets(List<Map<String, Object>> targets) {
        String origin = messages.get(0).origin();
        String host = messages.get(0).host().toLowerCase(Locale.ROOT);
        DefaultComboBoxModel<Item> tm = new DefaultComboBoxModel<>();
        tm.addElement(new Item(0, "(no target)", null));
        Item match = null;
        for (Map<String, Object> t : targets) {
            String address = Json.str(t, "address");
            Item it = new Item(Json.num(t, "id"), Json.str(t, "name") + (address.isEmpty() ? "" : "  " + address), t);
            tm.addElement(it);
            String a = address.toLowerCase(Locale.ROOT);
            if (match == null && !host.isEmpty() && (a.equals(origin.toLowerCase(Locale.ROOT)) || a.contains(host))) {
                match = it;
            }
        }
        Item create = null;
        if (!origin.isEmpty()) {
            create = new Item(-1, "New target: " + origin, null);
            tm.addElement(create);
        }
        target.setModel(tm);
        target.setSelectedItem(match != null ? match : create != null ? create : tm.getElementAt(0));
    }

    private void loadCwes() {
        background(api::cwes, rows -> {
            allCwes = rows;
            filterCwes();
        });
    }

    /**
     * List item for a CWE. Burp's theme replaces custom cell renderers, so the text comes from toString(), which the
     * default renderer uses.
     */
    private record Cwe(String[] value) {
        @Override
        public String toString() {
            return plain(value[0] + "  " + value[1]);
        }
    }

    private void filterCwes() {
        String q = cweSearch.getText().trim().toLowerCase(Locale.ROOT);
        String number = q.toUpperCase(Locale.ROOT).replace("CWE-", "").trim();
        cweModel.clear();
        List<String[]> exact = new ArrayList<>();
        List<String[]> rest = new ArrayList<>();
        String alias = CWE_ALIASES.getOrDefault(q, "");
        for (String[] c : allCwes) {
            if (q.isEmpty()) {
                (COMMON_CWES.contains(c[0]) ? exact : rest).add(c);
            } else if (c[0].equalsIgnoreCase("CWE-" + number) || c[0].equals(alias)) {
                exact.add(c);
            } else if (c[0].toLowerCase(Locale.ROOT).contains(q) || c[1].toLowerCase(Locale.ROOT).contains(q)) {
                rest.add(c);
            }
        }
        if (q.isEmpty()) {
            exact.sort(java.util.Comparator.comparingInt(c -> COMMON_CWES.indexOf(c[0])));
        }
        exact.addAll(rest);
        for (int k = 0; k < Math.min(CWE_RESULTS, exact.size()); k++) {
            cweModel.addElement(new Cwe(exact.get(k)));
        }
        if (!exact.isEmpty() && !q.isEmpty()) {
            cweList.setSelectedIndex(0);
        }
    }

    // ------------------------------------------------------------------- submit

    private void submit() {
        Item r = (Item) report.getSelectedItem();
        if (r == null) {
            status.setText("Choose a report.");
            return;
        }
        boolean isNew = modeNew.isSelected();
        if (isNew && title.getText().trim().isEmpty()) {
            status.setText("The title is required.");
            title.requestFocusInWindow();
            return;
        }
        Item existingFinding = (Item) existing.getSelectedItem();
        if (!isNew && existingFinding == null) {
            status.setText("Choose the finding.");
            return;
        }
        boolean withResponse = includeResponse.isSelected();
        settings.includeResponse(withResponse);
        settings.lastReport(r.id());
        List<Map<String, Object>> evidence = new ArrayList<>();
        String et = evidenceTitle.getText().trim();
        for (int k = 0; k < messages.size(); k++) {
            Message m = messages.get(k);
            String t = et.isEmpty() ? m.defaultTitle() : messages.size() == 1 ? et : et + " (" + (k + 1) + "/" + messages.size() + ")";
            evidence.add(m.evidence(t.length() > 300 ? t.substring(0, 300) : t, withResponse));
        }
        String findingTitle = title.getText().trim();
        String sev = SEVERITIES[severity.getSelectedIndex()][0];
        String cwe = chosenCwe;
        Item tgt = (Item) target.getSelectedItem();
        Message first = messages.get(0);

        send.setEnabled(false);
        status.setText("Sending ...");
        background(() -> {
            if (!isNew) {
                for (Map<String, Object> e : evidence) {
                    api.addEvidence(existingFinding.id(), e);
                }
                return api.finding(existingFinding.id());
            }
            List<Long> targetIds = new ArrayList<>();
            if (tgt != null && tgt.id() > 0) {
                targetIds.add(tgt.id());
            } else if (tgt != null && tgt.id() == -1) {
                targetIds.add(api.createTarget(r.id(), first.host(), "web", first.origin()));
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("title", findingTitle);
            body.put("severity", sev);
            body.put("status", "open");
            body.put("cwe", cwe);
            body.put("cvss_version", "");
            body.put("target_ids", targetIds);
            body.put("evidence", evidence);
            return api.createFinding(r.id(), body);
        }, finding -> {
            String id = Json.str(finding, "display_id");
            String url = Json.str(finding, "url");
            log.accept("Sent " + evidence.size() + " request(s) to " + id + " in \"" + r.label() + "\"");
            dispose();
            done(id, Json.str(finding, "title"), url, evidence.size());
        });
    }

    private void done(String id, String findingTitle, String url, int count) {
        String text = count + " request(s) added to " + id + " " + findingTitle + ".";
        Object[] options = url.isEmpty() || !Desktop.isDesktopSupported() ? new Object[] {"OK"} : new Object[] {"Open in ptreport", "OK"};
        int choice = JOptionPane.showOptionDialog(getOwner(), text, "ptreport", JOptionPane.DEFAULT_OPTION,
                JOptionPane.INFORMATION_MESSAGE, null, options, options[options.length - 1]);
        if (options.length == 2 && choice == 0) {
            try {
                URI uri = URI.create(url);
                if ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme())) {
                    Desktop.getDesktop().browse(uri);
                }
            } catch (Exception ex) {
                log.accept("Cannot open the browser: " + ex.getMessage());
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    private interface Task<T> {
        T run() throws ApiClient.ApiException;
    }

    /** Run an API call off the Swing thread; show its error in the dialog. */
    private <T> void background(Task<T> task, Consumer<T> onSuccess) {
        new SwingWorker<T, Void>() {
            private ApiClient.ApiException error;

            @Override
            protected T doInBackground() {
                try {
                    return task.run();
                } catch (ApiClient.ApiException e) {
                    error = e;
                    return null;
                }
            }

            @Override
            protected void done() {
                if (error != null) {
                    showError(error.describe());
                    send.setEnabled(report.getItemCount() > 0);
                    return;
                }
                try {
                    onSuccess.accept(get());
                } catch (Exception e) {
                    showError(e.getMessage());
                }
            }
        }.execute();
    }

    private void showError(String message) {
        String m = message == null ? "Unknown error" : message;
        if (m.contains("\n")) {
            status.setText("ptreport rejected the data (see details).");
            JTextArea area = new JTextArea(m, Math.min(10, m.split("\n").length + 1), 60);
            area.setEditable(false);
            area.setLineWrap(true);
            JOptionPane.showMessageDialog(this, new JScrollPane(area), "ptreport", JOptionPane.ERROR_MESSAGE);
        } else {
            status.setText(plain(m));
        }
        log.accept(m);
    }

    /**
     * Swing renders text starting with "<html>" as HTML. Burp disables HTML rendering anyway, so the extension only
     * uses plain text; this guard keeps data from ptreport plain on any other Swing host too.
     */
    static String plain(String s) {
        return s != null && s.regionMatches(true, 0, "<html", 0, 5) ? " " + s : s;
    }

}
