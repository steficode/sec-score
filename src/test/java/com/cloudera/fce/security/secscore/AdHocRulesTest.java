// (c) Copyright 2017 Cloudera, Inc.
package com.cloudera.fce.security.secscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.cloudera.fce.security.secscore.dto.Result;
import com.cloudera.fce.security.secscore.dto.ResultsSummary;
import com.cloudera.fce.security.secscore.dto.Rule;
import com.cloudera.fce.security.secscore.dto.RuleList;

import java.io.File;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import net.sf.saxon.s9api.Processor;
import net.sf.saxon.s9api.XdmNode;

import org.apache.commons.io.FileUtils;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * An example of running ad-hoc rules against the test data that currently
 * exists
 */
public class AdHocRulesTest {
    private static final String DESCRIPTION = "Cloudera Navigator.";
    private static RuleList ruleList;
    @BeforeClass
    public static void buildRule() {
        Rule rule = new Rule();
        rule.setRuleXPath(
            "/Security/deployment/ObjectNode/managementService[type='MGMT']/roles[type='NAVIGATOR']"
        );
        rule.setLevel(2);
        rule.setDescription(DESCRIPTION);
        rule.setFatal(false);
        rule.setPassMessage("Cloudera Navigator is installed.");
        rule.setErrorMessage("Cloudera Navigator is not installed");
        rule.setFailOnTrue(false);
        rule.setScore(1);
        List<Rule> rules = new ArrayList<Rule>();
        rules.add(rule);
        AdHocRulesTest.ruleList = new RuleList(rules);
    }

    @Test
    public void testNightly() throws Exception {
        File deploymentFile = FileUtils.toFile(BaseRulesTest.class
                .getClassLoader().getResource(
                        "configs/nightly/nightly-redacted.json"));
        File secInspectorFile = FileUtils.toFile(BaseRulesTest.class
                .getClassLoader().getResource(
                        "configs/nightly/nightly-sec-inspector.json"));

        Processor proc = new Processor(false);

        String deploymentJson = FileUtils.readFileToString(deploymentFile,
                Charset.defaultCharset());
        String secInspectorJson = FileUtils.readFileToString(secInspectorFile,
                Charset.defaultCharset());

        XdmNode xmlNode = SecScore.buildTestXml(deploymentJson,
                secInspectorJson, null, proc);
        ResultsSummary results = SecScore.executeRules(xmlNode, ruleList, proc,
                "Cluster 1", null).get(0);

        assertEquals(1, results.getResultList().size());
        // Check some specific results
        Result result = results.getResultList().get(0);
        assertEquals(DESCRIPTION, result.getDescription());
        assertTrue(result.isPass());
    }

    @Test
    public void testInternalEDH() throws Exception {
        File deploymentFile = FileUtils.toFile(BaseRulesTest.class
                .getClassLoader().getResource(
                        "configs/internaledh/internaledh-cm_deployment.json"));

        Processor proc = new Processor(false);

        String deploymentJson = FileUtils.readFileToString(deploymentFile,
                Charset.defaultCharset());

        XdmNode xmlNode = SecScore.buildTestXml(deploymentJson,
                null, null, proc);
        ResultsSummary results = SecScore.executeRules(xmlNode, ruleList, proc,
                "cluster", null).get(0);

        assertEquals(1, results.getResultList().size());
        // Check some specific results
        Result result = results.getResultList().get(0);
        assertEquals(DESCRIPTION, result.getDescription());
        assertTrue(result.isPass());
    }
}
