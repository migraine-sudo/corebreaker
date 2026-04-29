// libxml2 Schematron validation fuzzer
// Schematron is experimental/incomplete in libxml2 - higher bug probability

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/schematron.h>
#include <libxml/xmlerror.h>

static void silence_error(void *ctx, const char *msg, ...) {
    (void)ctx;
    (void)msg;
}

static void silence_structured(void *ctx, const xmlError *error) {
    (void)ctx;
    (void)error;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    xmlInitParser();
    xmlSetGenericErrorFunc(NULL, silence_error);
    xmlSetStructuredErrorFunc(NULL, silence_structured);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4)
        return 0;

    uint16_t split = ((uint16_t)data[0] << 8) | data[1];
    const uint8_t *payload = data + 2;
    size_t payload_size = size - 2;

    size_t schema_len = split % (payload_size + 1);
    size_t doc_len = payload_size - schema_len;

    if (schema_len == 0 || doc_len == 0)
        return 0;

    const char *schema_data = (const char *)payload;
    const char *doc_data = (const char *)(payload + schema_len);

    xmlSchematronParserCtxtPtr parser_ctxt =
        xmlSchematronNewMemParserCtxt(schema_data, (int)schema_len);
    if (parser_ctxt == NULL)
        return 0;

    xmlSchematronPtr schema = xmlSchematronParse(parser_ctxt);
    xmlSchematronFreeParserCtxt(parser_ctxt);

    if (schema == NULL)
        return 0;

    xmlSchematronValidCtxtPtr valid_ctxt =
        xmlSchematronNewValidCtxt(schema, XML_SCHEMATRON_OUT_QUIET);
    if (valid_ctxt == NULL) {
        xmlSchematronFree(schema);
        return 0;
    }

    xmlDocPtr doc = xmlReadMemory(doc_data, (int)doc_len,
                                  "fuzz.xml", NULL,
                                  XML_PARSE_NONET | XML_PARSE_NOENT);
    if (doc != NULL) {
        xmlSchematronValidateDoc(valid_ctxt, doc);
        xmlFreeDoc(doc);
    }

    xmlSchematronFreeValidCtxt(valid_ctxt);
    xmlSchematronFree(schema);

    return 0;
}
