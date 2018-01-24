// (c) Copyright 2017 Cloudera, Inc.
package com.cloudera.fce.security.secscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.cloudera.fce.security.secscore.dto.Result;
import com.cloudera.fce.security.secscore.dto.ResultsSummary;
import com.cloudera.fce.security.secscore.dto.RuleList;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.nio.charset.Charset;
import java.util.List;

import net.sf.saxon.s9api.Processor;
import net.sf.saxon.s9api.XdmNode;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

/**
 * Test of the basic rules that were written before security summit. This is an
 * example of how to write/run tests against multiple config changes.
 */
public class BaseRulesTest {
    public static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void testNightly() throws Exception {
        File deploymentFile = FileUtils.toFile(BaseRulesTest.class
                .getClassLoader().getResource(
                        "configs/nightly/nightly-redacted.json"));
        File secInspectorFile = FileUtils.toFile(BaseRulesTest.class
                .getClassLoader().getResource(
                        "configs/nightly/nightly-sec-inspector.json"));
        RuleList rules = MAPPER.readValue(BaseRulesTest.class.getClassLoader()
                .getResource("rules/base-rules.json"), RuleList.class);

        Processor proc = new Processor(false);

        String deploymentJson = FileUtils.readFileToString(deploymentFile,
                Charset.defaultCharset());
        String secInspectorJson = FileUtils.readFileToString(secInspectorFile,
                Charset.defaultCharset());

        XdmNode xmlNode = SecScore.buildTestXml(deploymentJson,
                secInspectorJson, null, proc);
        ResultsSummary results = SecScore.executeRules(xmlNode, rules, proc,
                "Cluster 1", null).get(0);

        // Verify there were 20 rules run
        assertEquals(20, results.getResultList().size());
        // Check some specific results
        Result httpfsTls = getResultByDescription(results.getResultList(),
                "HDFS HTTPFS TLS");
        assertNotNull(httpfsTls);
        assertTrue(httpfsTls.isPass());
        Result cmLdap = getResultByDescription(results.getResultList(),
                "Cloudera Manager configured to use LDAPS rather than LDAP");
        assertNotNull(cmLdap);
        assertFalse(cmLdap.isPass());
    }

    @Test
    public void testInternalEDH() throws Exception {
        File deploymentFile = FileUtils.toFile(BaseRulesTest.class
                .getClassLoader().getResource(
                        "configs/internaledh/internaledh-cm_deployment.json"));
        File secInspectorFile = null;
        RuleList rules = MAPPER.readValue(BaseRulesTest.class.getClassLoader()
                .getResource("rules/base-rules.json"), RuleList.class);

        Processor proc = new Processor(false);

        String deploymentJson = FileUtils.readFileToString(deploymentFile,
                Charset.defaultCharset());

        XdmNode xmlNode = SecScore.buildTestXml(deploymentJson,
                null, null, proc);
        ResultsSummary results = SecScore.executeRules(xmlNode, rules, proc,
                "cluster", null).get(0);

        // Verify there were 20 rules run
        assertEquals(20, results.getResultList().size());
        // Check some specific results
        Result httpfsTls = getResultByDescription(results.getResultList(),
                "HDFS HTTPFS TLS");
        assertNotNull(httpfsTls);
        assertFalse(httpfsTls.isPass());
        Result cmLdap = getResultByDescription(results.getResultList(),
                "Cloudera Manager configured to use LDAPS rather than LDAP");
        assertNotNull(cmLdap);
        assertFalse(cmLdap.isPass());
        Result hdfsEncryptedTransport = getResultByDescription(
                results.getResultList(), "HDFS encrypted data transport");
        assertNotNull(hdfsEncryptedTransport);
        assertTrue(hdfsEncryptedTransport.isPass());
    }

    public static Result getResultByDescription(List<Result> results,
            String description) {
        for (Result r : results) {
            if (r.getDescription().equals(description)) {
                return r;
            }
        }
        return null;
    }
}
