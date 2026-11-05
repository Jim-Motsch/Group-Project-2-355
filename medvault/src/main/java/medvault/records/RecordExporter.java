package medvault.records;

import medvault.model.Patient;

/**
 * Exports a chart as an HTML page for printing or sharing with another clinic.
 *
 * <p><b>CWE-79: Cross-site Scripting.</b> Every value from the chart is
 * HTML-escaped ({@code & < > " '}) before it is placed in the page, so notes
 * containing {@code <script>} render as text.</p>
 *
 * @author James Strickert
 */
public class RecordExporter {

    /**
     * @param patient chart to export (access already checked by the caller)
     * @return a complete, safe HTML document
     */
    public String toHtml(Patient patient) {
        // TODO(James) CWE-79
        throw new UnsupportedOperationException("TODO(James): CWE-79");
    }
}
