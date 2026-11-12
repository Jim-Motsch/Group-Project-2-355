package medvault.records;

import medvault.model.Patient;
import medvault.model.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathFactoryConfigurationException;
import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Imports patient charts sent by another clinic as XML.
 *
 * <p>Expected format:</p>
 * <pre>{@code
 * <patients>
 *   <patient id="1">
 *     <name>...</name> <dob>1980-01-31</dob> <attending>dr.grey</attending> <notes>...</notes>
 *   </patient>
 * </patients>
 * }</pre>
 *
 * <p><b>CWE-611: Improper Restriction of XML External Entity Reference.</b>
 * A default Java XML parser will follow
 * {@code <!ENTITY x SYSTEM "file:///etc/passwd">} and paste that file into
 * the document (or fetch a URL from inside the network). The parser here
 * refuses any DOCTYPE declaration outright, and as further layers turns off
 * external general and parameter entities, external DTD loading, XInclude
 * and entity expansion, and blocks all external DTD/schema access. A file
 * containing a DOCTYPE is rejected with a {@link ValidationException}.</p>
 *
 * <p>Name lookups use a fixed XPath expression with a {@code $name} variable,
 * filled in by an {@link javax.xml.xpath.XPathVariableResolver}, so the
 * user's text is only ever compared as a value and never becomes part of the
 * expression.</p>
 *
 * @author James Strickert
 */
public class XmlRecordImporter {

    private static final String FIND_BY_NAME = "/patients/patient[name = $name]";
    private static final QName NAME_VARIABLE = new QName("name");
    private static final String REJECTED =
            "The import file was rejected: it is not valid MedVault XML or it contains a DOCTYPE.";

    /**
     * @param xml untrusted XML document
     * @return parsed document
     * @throws medvault.model.ValidationException if the XML is malformed or uses a DTD
     */
    public Document parse(InputStream xml) {
        if (xml == null) {
            throw new ValidationException(REJECTED);
        }
        try {
            DocumentBuilder builder = hardenedFactory().newDocumentBuilder();
            builder.setErrorHandler(SILENT); // otherwise the parser prints errors to stderr
            Document doc = builder.parse(xml);
            Element root = doc.getDocumentElement();
            if (root == null || !"patients".equals(root.getTagName())) {
                throw new ValidationException(REJECTED);
            }
            return doc;
        } catch (SAXException | IOException e) {
            throw new ValidationException(REJECTED);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("secure XML parser unavailable", e);
        }
    }

    /**
     * @param doc         a parsed import
     * @param patientName untrusted name to look up
     * @return matching charts in the document
     * @throws ValidationException if a matching entry is malformed
     */
    public List<Patient> findByName(Document doc, String patientName) {
        if (doc == null || patientName == null) {
            return List.of();
        }
        NodeList matches;
        try {
            XPathFactory factory = XPathFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); // no extension functions
            XPath xpath = factory.newXPath();
            // The user's value is bound to $name; it never becomes part of the expression text.
            xpath.setXPathVariableResolver(var -> NAME_VARIABLE.equals(var) ? patientName : null);
            XPathExpression expr = xpath.compile(FIND_BY_NAME);
            matches = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
        } catch (XPathExpressionException | XPathFactoryConfigurationException e) {
            throw new IllegalStateException("XPath lookup failed", e);
        }
        List<Patient> result = new ArrayList<>(matches.getLength());
        for (int i = 0; i < matches.getLength(); i++) {
            result.add(toPatient((Element) matches.item(i)));
        }
        return result;
    }

    private static DocumentBuilderFactory hardenedFactory() throws ParserConfigurationException {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        f.setNamespaceAware(false);
        f.setValidating(false);
        return f;
    }

    private static Patient toPatient(Element e) {
        try {
            String idText = e.getAttribute("id");
            long id = idText.isEmpty() ? 0 : Long.parseLong(idText);
            String name = child(e, "name", true);
            LocalDate dob = LocalDate.parse(child(e, "dob", true));
            String attending = child(e, "attending", true);
            String notes = child(e, "notes", false);
            return new Patient(id, name, dob, attending, notes);
        } catch (NumberFormatException | DateTimeParseException bad) {
            throw new ValidationException("The import file contains a malformed patient entry.");
        }
    }

    /** Text of the first direct child element with this tag. */
    private static String child(Element parent, String tag, boolean required) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE && tag.equals(n.getNodeName())) {
                return n.getTextContent().trim();
            }
        }
        if (required) {
            throw new ValidationException("The import file contains a malformed patient entry.");
        }
        return "";
    }

    /** Turns every parser warning and error into a rejection, without printing anything. */
    private static final ErrorHandler SILENT = new ErrorHandler() {
        @Override
        public void warning(SAXParseException e) {
            // ignored
        }

        @Override
        public void error(SAXParseException e) throws SAXException {
            throw e;
        }

        @Override
        public void fatalError(SAXParseException e) throws SAXException {
            throw e;
        }
    };
}
