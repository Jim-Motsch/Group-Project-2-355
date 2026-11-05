package medvault.records;

import medvault.model.Patient;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.util.List;

/**
 * Imports patient charts sent by another clinic as XML.
 *
 * <p><b>CWE-611: Improper Restriction of XML External Entity Reference.</b>
 * The parser disables DOCTYPE declarations and external entities, so a file
 * containing {@code <!ENTITY x SYSTEM "file:///etc/passwd">} is rejected.</p>
 *
 * <p><b>CWE-643: XPath Injection.</b> Lookups inside the imported document
 * use an {@link javax.xml.xpath.XPathVariableResolver} for user values, never
 * string-built XPath expressions.</p>
 *
 * @author James Strickert
 */
public class XmlRecordImporter {

    /**
     * @param xml untrusted XML document
     * @return parsed document
     * @throws medvault.model.ValidationException if the XML is malformed or uses a DTD
     */
    public Document parse(InputStream xml) {
        // TODO(James) CWE-611: DocumentBuilderFactory with
        //  "http://apache.org/xml/features/disallow-doctype-decl" = true, XInclude off, expandEntityReferences off.
        throw new UnsupportedOperationException("TODO(James): CWE-611");
    }

    /**
     * @param doc         a parsed import
     * @param patientName untrusted name to look up
     * @return matching charts in the document
     */
    public List<Patient> findByName(Document doc, String patientName) {
        // TODO(James) CWE-643: XPath "/patients/patient[name=$name]" with a variable resolver.
        throw new UnsupportedOperationException("TODO(James): CWE-643");
    }
}
