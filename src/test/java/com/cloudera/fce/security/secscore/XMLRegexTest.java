package com.cloudera.fce.security.secscore;
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

import junit.framework.Assert;
import org.junit.Test;

public class XMLRegexTest {

    @Test
    public void testSimpleXML() throws Exception {
        String xml = "<foo>&lt;abc>&lt;/abc></foo>";
        Assert.assertEquals("<foo><abc></abc></foo>", SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testEmptyElement() throws Exception {
        String xml = "<foo>&lt;abc>def&lt;/abc></foo>";
        Assert.assertEquals("<foo><abc>def</abc></foo>", SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testLdapPlaceholderElement() throws Exception {
        String xml = "<foo>something=&lt;username>def</foo>";
        //Assert.assertEquals("<foo>something=&lt;username>def</foo>", SecScore.fixXmlIssues(xml));
        Assert.assertEquals("<foo>something=def</foo>", SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testSimpleHueElement() throws Exception {
        String xml = "<foo>http://&lt;sparkurl>:8899</foo>";
        Assert.assertEquals("<foo>http://&lt;sparkurl>:8899</foo>",
                SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testXMLComment() throws Exception {
        String xml = "<foo>&lt;!-- this is a comment with load of stuff in --></foo>";
        Assert.assertEquals("<foo><!-- this is a comment with load of stuff in --></foo>",
                SecScore.fixXmlIssues(xml));
    }

    //@Test
    //public void testNonXMLXML() throws Exception {
    //    String xml = "<foo>sometext&lt;lonelyelement>somemoretext</foo>";
    //    Assert.assertEquals("<foo>sometext&lt;lonelyelement>somemoretext</foo>",
    //                        SecScore.fixXmlIssues(xml));
    //}

    @Test
    public void testSSLDirective() throws Exception {
        String xml = "<foo>&lt;IfModule !something>abc&lt;/IfModule></foo>";
        Assert.assertEquals("<foo><IfModule>abc</IfModule></foo>",
                SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testSSLDirective2() throws Exception {
        String xml =
                "<value>SSLCertificateChainFile /opt/cloudera/security/CAcerts/ca-chain.cert.pem\n"+
            "SSLProxyCACertificateFile /opt/cloudera/security/CAcerts/ca-chain.cert.pem\n"+
            "SSLProxyVerify none\n"+
            "SSLProxyCheckPeerCN off\n"+
            "SSLProxyCheckPeerName off\n"+
            "<IfModule !socache_shmcb_module>\n"+
            "LoadModule socache_shmcb_module /usr/lib/apache2/modules/mod_socache_shmcb.so\n"+
            "</IfModule>\n"+
            "SSLSessionCache shmcb:/run/shm/ssl_scache(512000)</value>";
        String targetXml =
                "<value>SSLCertificateChainFile /opt/cloudera/security/CAcerts/ca-chain.cert.pem\n"+
                "SSLProxyCACertificateFile /opt/cloudera/security/CAcerts/ca-chain.cert.pem\n"+
                "SSLProxyVerify none\n"+
                "SSLProxyCheckPeerCN off\n"+
                "SSLProxyCheckPeerName off\n"+
                "<IfModule>\n"+
                "LoadModule socache_shmcb_module /usr/lib/apache2/modules/mod_socache_shmcb.so\n"+
                "</IfModule>\n"+
                "SSLSessionCache shmcb:/run/shm/ssl_scache(512000)</value>";
        Assert.assertEquals(targetXml, SecScore.fixXmlIssues(xml));
    }

    @Test
    public void replaceNullCharCodes() throws Exception {
        String xml = "<name>oozie.poller.timeout.millis</name>&#xd;\n" +
                "<value>20000</value>&#xd;\n";
        Assert.assertEquals("<name>oozie.poller.timeout.millis</name>\n" +
                "<value>20000</value>\n", SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testElementWithAttributes() throws Exception {
        String xml =
            "<foo>&lt;element with=\"attributes\"  with=\"another attribute\">bar&lt;" +
                    "/element></foo>";
        Assert.assertEquals(
             "<foo><element with=\"attributes\"  with=\"another attribute\">bar</element></foo>",
                SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testNestedElement() throws Exception {
        String xml = "<foo>&lt;abc>&lt;def>&lt;/def>&lt;/abc></foo>";
        Assert.assertEquals("<foo><abc><def></def></abc></foo>",
                SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testStrangeEmailElement() throws Exception {
        String xml = "<abc@def>";
        Assert.assertEquals("<abcdef/>", SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testRemoveBannerHTML() throws Exception {
        String xml = "<name>banner_html</name><value>'</pre><div>"
                + "<i class=\"&amp;quot;fa\"></i> My cluster</div><pre>'</value>";
        Assert.assertEquals("<name>banner_html</name><value></value>",
                SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testRedactedBrokenElements() throws Exception {
        String xml = "<basicRegistry id=\"basic\" realm=\"ibm\">     \t\n" +
                "   <user name=REDACTED\n" +
                "   <user name=REDACTED\n" +
                "   <user name=REDACTED\n" +
                "   <group name=\"group1\">\n" +
                "   <member name=\"admin\" />\n" +
                "   <member name=\"qauser1\" />\n" +
                "   <member name=\"qauser2\" />\n" +
                "   </group>\n" +
                "   <group name=\"group2\">\n" +
                "   <member name=\"admin\" />\n" +
                "   <member name=\"qauser1\" />\n" +
                "   </group>\n" +
                "</basicRegistry>";
        String targetXml = "<basicRegistry id=\"basic\" realm=\"ibm\">     \t\n" +
                "   <user name=\"REDACTED\" />\n" +
                "   <user name=\"REDACTED\" />\n" +
                "   <user name=\"REDACTED\" />\n" +
                "   <group name=\"group1\">\n" +
                "   <member name=\"admin\" />\n" +
                "   <member name=\"qauser1\" />\n" +
                "   <member name=\"qauser2\" />\n" +
                "   </group>\n" +
                "   <group name=\"group2\">\n" +
                "   <member name=\"admin\" />\n" +
                "   <member name=\"qauser1\" />\n" +
                "   </group>\n" +
                "</basicRegistry>";
        Assert.assertEquals(targetXml, SecScore.fixXmlIssues(xml));
    }

    @Test
    public void testAlertTrigger() throws Exception {
        String xml = "<value>[\n" +
                "  {\n" +
                "    \"triggerName\": \"Admin node free memory below 5%\",\n" +
                "    \"triggerExpression\": \"IF (select 100 * physical_memory_memfree "
                + "/ physical_memory_total where hostname rlike '.*admin.*' and last(100 * physi"
                + " cal_memory_memfree / physical_memory_total) &lt;5) DO health:concerning \",\n" +
                "    \"streamThreshold\": 0,\n" +
                "    \"enabled\": false\n" +
                "  }\n" +
                "]</value>";

        Assert.assertEquals(xml, SecScore.fixXmlIssues(xml));
    }

}
