package com.cloudera.fce.security.secscore.ruletests;
/*
 * Licensed to Cloudera, Inc. under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  Cloudera, Inc. licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.cloudera.fce.security.secscore.SecScore;
import com.cloudera.fce.security.secscore.dto.Rule;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import net.sf.saxon.s9api.DocumentBuilder;
import net.sf.saxon.s9api.Processor;
import net.sf.saxon.s9api.QName;
import net.sf.saxon.s9api.XPathCompiler;
import net.sf.saxon.s9api.XdmNode;
import org.junit.Assert;
import org.junit.Ignore;

import javax.xml.transform.stream.StreamSource;
import java.io.File;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

@Ignore
public abstract class AbstractRulesTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Map<Integer, Rule> RULE_CACHE = new HashMap<Integer, Rule>(2);

    public void executeRuleTests(File ruleTestFile) throws Exception {
        ArrayNode rulesTests = (ArrayNode)MAPPER.readTree(ruleTestFile).findPath("ruleTest");

        for (JsonNode rule : rulesTests) {
            String xml = rule.get("xml").asText();
            int ruleId = rule.get("ruleId").asInt();
            boolean expectedResult = rule.get("expectedResult").asBoolean();

            Rule targetRule = getRule(ruleId);

            Processor proc = new Processor(false);
            XPathCompiler xpath = proc.newXPathCompiler();
            xpath.declareVariable(new QName(SecScore.CLUSTER_NAME_VARIABLE));

            StringReader sr = new StringReader(xml);
            StreamSource ss = new StreamSource(sr);
            DocumentBuilder builder = proc.newDocumentBuilder();

            XdmNode xdmDocument = builder.build(ss);
            Assert.assertEquals("RuleId: " + ruleId + " " + xml, expectedResult,
                    SecScore.executeRule(xdmDocument, targetRule, xpath,
                            SecScore.CLUSTER_NAME_VARIABLE).isPass());
        }

    }

    private static Rule getRule(int ruleId) {
        Rule targetRule = RULE_CACHE.get(ruleId);
        if (targetRule == null) {
            for (Rule rule : SecScore.getDefaultRuleList().getRuleList()) {
                if (rule.getId() == ruleId) {
                    targetRule = rule;
                    RULE_CACHE.put(ruleId, rule);
                    break;
                }
            }
        }
        return targetRule;
    }
}
